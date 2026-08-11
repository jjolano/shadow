#import "RestrictionEngine.h"
#import "RestrictionResolver.h"
#import "RulesetStore.h"
#import <Shadow/Core.h>
#import <Shadow/Core+Utilities.h>
#import <Shadow/Ruleset.h>
#import <Shadow/JBPath.h>

#import <limits.h>
#import <unistd.h>

// The Candidate 5 cutover is done: the resolver-based engine is THE path
// engine. It ran alongside the legacy evaluator in shadow mode — every query
// answered by both, divergences logged — until parity held across the harness
// (RestrictionTests 214/214 rooted and rootless, 20,000 fuzz iterations, zero
// mismatches), at which point the legacy evaluator and its two caches were
// deleted. Running both in production cost 2x on the hottest path in the
// tweak, which is a launch-watchdog-sized amount of work (see
// shdw_addr_is_restricted in ShadowCore's hooks.h for the other half).
//
// tests/RestrictionTests.m still asserts every verdict this pipeline produces;
// it just no longer has a second engine to compare against.

// How long a cached decision is honored (see the cache notes below).
// Trimmed from 2.0s (plan C0-1): a "not restricted" verdict for a
// nonexistent path is cached, and if the jailbreak file appears within the
// window a probe gets a stale "allowed". Ruleset reloads already invalidate
// via the generation tag; this shrinks the filesystem-appearance window.
static const NSTimeInterval kShadowDecisionCacheTTL = 0.5;

// Restricted roots that never hold legitimate app data: the rootless /var/jb
// fast-path, its canonical target (/var/jb is a symlink to
// /private/preboot/<hash>/jb on rootless) and rooted /cores crash dumps.
// On roothide there is no /var/jb at all — the jailbreak root is a
// random-named jbroot resolved through jbroot() — so that prefix check is
// replaced by a live-jbroot check. Moved verbatim from Core.m.
static BOOL shdwIsPathInRestrictedRoot(NSString* path) {
#ifdef SHADOW_ROOTHIDE
    // roothide: jbroot() already returns the full jailbreak root path for
    // the current process; resolve it once and prefix-check it.
    static NSString* roothideRoot = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        NSString* root = jbroot(@"/");
        roothideRoot = [root hasSuffix:@"/"] ? root : [root stringByAppendingString:@"/"];
    });

    if(path && roothideRoot && [path hasPrefix:roothideRoot]) {
        return YES;
    }

    return NO;
#else
    // Canonical rootless jbroot target, resolved once. nil when not rootless
    // (realpath("/var/jb") fails), so the jbroot check is a no-op there.
    static NSString* jbrootTarget = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        char resolved[PATH_MAX];

        if(realpath("/var/jb", resolved)) {
            jbrootTarget = [NSString stringWithUTF8String:resolved];
        }
    });

    if([path hasPrefix:@"/var/jb"]
        || [path hasPrefix:@"/cores/"]
        || [path hasPrefix:@"/private/preboot"]) {
        return YES;
    }

    if(jbrootTarget && [path hasPrefix:jbrootTarget]) {
        return YES;
    }

    return NO;
#endif
}

// Per-process context from the Shadow facade, captured lazily: the engine is
// created during +[Shadow init] (via the backend), so reading
// +[Shadow sharedInstance] eagerly would deadlock the dispatch_once.
static BOOL shdw_context_ready = NO;
static ShadowRestrictionContext shdw_ctx;

static void shdwEnsureContext(void) {
    if(!shdw_context_ready) {
        Shadow* shadow = [Shadow sharedInstance];
        shdw_ctx.hasAppSandbox = shadow.hasAppSandbox;
        shdw_ctx.rootless = shadow.rootless;
        shdw_ctx.bundlePath = shadow.bundlePath;
        shdw_ctx.homePath = shadow.homePath;
        shdw_context_ready = YES;
    }
}

// Ruleset passes against one immutable snapshot: pass 1 compliance (hard
// veto), then whitelist (wins over blacklist), then blacklist. Shared by both
// backend evaluators — identical matching on the same snapshot, so the two
// engines can only ever differ in the layers above (resolution, gates,
// caches). Verdict-equivalent to the legacy three-loop shape.
static BOOL shdwSnapshotDeniesPath(ShadowRulesetSnapshot* snapshot, NSString* path) {
    // pass 1: compliance (hard veto)
    for(RulesetEngine* ruleset in snapshot.rulesets) {
        if(![ruleset isPathCompliant:path]) {
            return YES;
        }
    }

    // pass 2: whitelist (any ruleset whitelisting the path vetoes a blacklist)
    for(RulesetEngine* ruleset in snapshot.rulesets) {
        if([ruleset isPathWhitelisted:path]) {
            return NO;
        }
    }

    // pass 3: blacklist
    for(RulesetEngine* ruleset in snapshot.rulesets) {
        if([ruleset isPathBlacklisted:path]) {
            return YES;
        }
    }

    return NO;
}

@implementation ShadowRestrictionEngine {
    ShadowRulesetStore* store;
    ShadowRestrictionResolver* resolver; // lazy (needs shdwEnsureContext)

    // The SINGLE generation-aware decision cache (Candidate 5: replaces both
    // the old Core.m decisionCache and Backend.m cache_restricted). Split per
    // tier so no per-probe key namespacing is needed:
    //   - sharedCache (tier 1, top-level verdicts): key = raw query path, or
    //     a length-prefixed joined workingDir+entry string for the
    //     working-dir composite (same key shapes as the old decisionCache;
    //     the resolved abs path is also probed under the tier-2 entries).
    //   - backendCache (tier 2, backend evaluation incl. parent recursion):
    //     key = plain normalized absolute path, gen-checked like the old
    //     cache_restricted but with the same TTL as tier 1 — a strictly
    //     smaller staleness window than the old generation-only backend
    //     cache.
    // Entries are @[computedTime, packed(generation << 1 | verdict)] (one
    // NSNumber instead of two) and are honored only within
    // kShadowDecisionCacheTTL and while the generation matches.
    NSCache* sharedCache;
    NSCache* backendCache;
}

- (instancetype)initWithStore:(ShadowRulesetStore *)rulesetStore {
    if((self = [super init])) {
        store = rulesetStore;
        sharedCache = [NSCache new];
        [sharedCache setCountLimit:1024];
        backendCache = [NSCache new];
        [backendCache setCountLimit:1024];
    }

    return self;
}

- (ShadowRestrictionResolver *)_resolver {
    if(!resolver) {
        shdwEnsureContext();
        resolver = [[ShadowRestrictionResolver alloc] initWithContext:shdw_ctx];
    }

    return resolver;
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

- (BOOL)isPathRestrictedQuery:(ShadowRestrictionQuery *)query {
    @autoreleasepool {
        return [self _newPathRestrictedQuery:query];
    }
}

- (BOOL)isPathRestricted:(NSString *)path {
    return [self isPathRestrictedQuery:[ShadowRestrictionQuery queryWithPath:path]];
}

- (BOOL)isSchemeRestricted:(NSString *)scheme {
    if(!scheme || [scheme length] == 0) {
        return NO;
    }

    [store checkForChanges];

    // C0-3: compare case-insensitively — detectors probe case variants
    // ("Cydia", "SILEO") to dodge exact matches. The exceptions must stay
    // case-insensitive here (a "File" probe must never be denied); the
    // ruleset pass needs no lowercase at this level — Ruleset.m normalizes
    // the query itself (isSchemeRestricted:) against entries that are
    // lowercased at load, so lowercasing twice is redundant.
    if([scheme caseInsensitiveCompare:@"file"] == NSOrderedSame
        || [scheme caseInsensitiveCompare:@"http"] == NSOrderedSame
        || [scheme caseInsensitiveCompare:@"https"] == NSOrderedSame) {
        return NO;
    }

    ShadowRulesetSnapshot* snapshot = [store currentSnapshot];

    for(RulesetEngine* ruleset in snapshot.rulesets) {
        if([ruleset isSchemeRestricted:scheme]) {
            return YES;
        }
    }

    return NO;
}

// C0-3: ruleset-driven bundle-ID check (the static well-known list lives in
// -[Shadow isBundleIDRestricted:], which consults this for the user-extensible
// half). No lowercase here: Ruleset.m normalizes the query itself
// (isBundleIDRestricted:) against entries lowercased at load.
- (BOOL)isBundleIDRestricted:(NSString *)bundleID {
    if(!bundleID || [bundleID length] == 0) {
        return NO;
    }

    [store checkForChanges];

    ShadowRulesetSnapshot* snapshot = [store currentSnapshot];

    for(RulesetEngine* ruleset in snapshot.rulesets) {
        if([ruleset isBundleIDRestricted:bundleID]) {
            return YES;
        }
    }

    return NO;
}

- (NSUInteger)rulesetGeneration {
    return [store generation];
}

// ---------------------------------------------------------------------------
// NEW engine (resolver + snapshot evaluation + single cache)
// ---------------------------------------------------------------------------

// Single-cache probe: -1 = miss (or stale), else the cached verdict (0/1).
// Both tiers use the same @[time, packed(generation << 1 | verdict)] entry
// shape; the packed NSNumber is decoded in place, so a hit allocates nothing.
- (NSInteger)_cachedVerdictForKey:(id)key generation:(NSUInteger)gen cache:(NSCache *)cache {
    NSArray* cached = [cache objectForKey:key];

    if(cached) {
        double age = [NSDate timeIntervalSinceReferenceDate] - [[cached objectAtIndex:0] doubleValue];

        if(age >= 0 && age <= kShadowDecisionCacheTTL) {
            unsigned long long v = [[cached objectAtIndex:1] unsignedLongLongValue];

            if((NSUInteger)(v >> 1) == gen) {
                return (NSInteger)(v & 1);
            }
        }
    }

    return -1;
}

- (void)_storeVerdict:(BOOL)verdict forKey:(id)key generation:(NSUInteger)gen cache:(NSCache *)cache {
    // Packed as (generation << 1) | restricted — one NSNumber per entry,
    // same shape as the legacy backend cache.
    [cache setObject:@[@([NSDate timeIntervalSinceReferenceDate]), @(((unsigned long long)gen << 1) | (verdict ? 1 : 0))] forKey:key];
}

// The new top-level pipeline: resolver stages (tilde, working-dir join,
// standardization, sandbox exemption, resolve-before-exempt alias, no-follow)
// feeding the new evaluation; structurally identical to the legacy flow so
// the differential's only degrees of freedom are the resolution helpers and
// the cache.
- (BOOL)_newPathRestrictedQuery:(ShadowRestrictionQuery *)query {
    @autoreleasepool {
        if(!query) {
            return NO;
        }

        shdwEnsureContext();
        ShadowRestrictionResolver* r = [self _resolver];
        NSString* path = query.path;

        if(!path || [path length] == 0 || [path isEqualToString:@"/"]) {
            return NO;
        }

        // Cacheability is exactly the legacy rule: default-shaped (read,
        // resolve-on, no working dir) absolute queries are cached under the
        // raw path; working-dir-only queries under a joined (wd, path)
        // string. The key is length-prefixed ("%lu:%@%@") so it is
        // unambiguous between different (wd, path) pairs and can never
        // collide with an absolute-path key (which starts with "/").
        BOOL defaultQuery = (query.operation == ShadowRestrictionOperationRead)
            && (query.flags == ShadowRestrictionFlagResolve);
        BOOL cacheable = defaultQuery && (query.workingDirectory == nil) && [path isAbsolutePath];
        id cacheKey = path;

        if(!cacheable && defaultQuery && query.workingDirectory
            && [query.workingDirectory isAbsolutePath] && ![path isAbsolutePath] && ![path hasPrefix:@"~"]) {
            cacheKey = [NSString stringWithFormat:@"%lu:%@%@", (unsigned long)[query.workingDirectory length], query.workingDirectory, path];
            cacheable = YES;
        }

        if(cacheable) {
            NSInteger cached = [self _cachedVerdictForKey:cacheKey generation:[store generation] cache:sharedCache];

            if(cached >= 0) {
                return (BOOL)cached;
            }
        }

        BOOL restricted = NO;

        // Tilde: deny on unresolvable user; expand otherwise.
        NSString* expanded = [r expandTilde:path];

        if(!expanded) {
            return NO;
        }

        path = expanded;

        // Relative paths join the working directory (or process cwd).
        if(![path isAbsolutePath]) {
            path = [r joinWorkingDirectory:path workingDirectory:query.workingDirectory];
        }

        // Standardize.
        path = [r standardizePath:path];

        // Run checks if path is outside the app sandbox.
        BOOL shouldCheckPath = ![r isSandboxExempt:path];

        // Resolve-before-exempt (see the legacy comment above). The resolver
        // owns the per-thread realpath guard, so no check is needed here.
        BOOL noFollow = (query.flags & ShadowRestrictionFlagNoFollow) != 0;

        if(!shouldCheckPath && !noFollow) {
            NSString* resolved = [r resolveTarget:path];

            if(resolved) {
                BOOL resolvedRestricted = shdwIsPathInRestrictedRoot(resolved)
                    || [self _newEvaluatePathRestriction:resolved query:query];

                if(resolvedRestricted) {
                    restricted = YES;
                    goto done;
                }
            }
        }

        if(shouldCheckPath) {
            if([self _newEvaluatePathRestriction:path query:query]) {
                restricted = YES;
                goto done;
            }
        }

        // Resolve into full path and check again (resolve flag off for the
        // sub-query, exactly like the legacy pipeline).
        if(query.flags & ShadowRestrictionFlagResolve) {
            NSString* resolved_path = [path stringByStandardizingPath];

            if(![resolved_path isEqualToString:path]) {
                ShadowRestrictionQuery* sub = [ShadowRestrictionQuery queryWithPath:resolved_path];
                sub.workingDirectory = query.workingDirectory;
                sub.operation = query.operation;
                sub.flags = query.flags & ~ShadowRestrictionFlagResolve;

                if([self _newPathRestrictedQuery:sub]) {
                    restricted = YES;
                    goto done;
                }
            }
        }

        done:
        if(cacheable) {
            [self _storeVerdict:restricted forKey:cacheKey generation:[store generation] cache:sharedCache];
        }

        return restricted;
    }
}

// The new gate + backend stage: rootless fast-paths, existence gates, then
// the snapshot evaluation. Mirrors the legacy evaluatePathRestriction: 1:1.
- (BOOL)_newEvaluatePathRestriction:(NSString *)path query:(ShadowRestrictionQuery *)query {
    BOOL isWrite = (query.operation == ShadowRestrictionOperationWrite);

    if(shdw_ctx.rootless) {
        if(shdwIsPathInRestrictedRoot(path)) {
            return YES;
        }

        BOOL checkable = [path hasPrefix:@"/var"]
            || [path hasPrefix:@"/private/preboot"]
            || [path hasPrefix:@"/usr/lib"];

        if(!checkable) {
            if(!isWrite) {
                NSString* jbpath = [@"/var/jb" stringByAppendingString:path];
                int errno_old = errno;
                BOOL exists = (access([jbpath fileSystemRepresentation], F_OK) == 0);
                errno = errno_old;

                if(!exists) {
                    return NO;
                }
            }

            if([self _newBackendPathRestricted:path]) {
                NSLog(@"[Shadow] isPathRestricted: restricted path: %@", path);
                return YES;
            }

            return NO;
        }
    }

    if([path hasPrefix:@"/usr/lib"]) {
        if(!isWrite) {
            int errno_old = errno;
            NSString* check_path = path;

            if(shdw_ctx.rootless) {
                check_path = [@"/var/jb" stringByAppendingString:path];
            }

            if(access([check_path fileSystemRepresentation], F_OK) != 0) {
                errno = errno_old;
                return NO;
            }
        }
    }

    if([self _newBackendPathRestricted:path]) {
        NSLog(@"[Shadow] isPathRestricted: restricted path: %@", path);
        return YES;
    }

    return NO;
}

// The new backend evaluation: shared passes over one snapshot, parent
// recursion, all behind the tier-2 cache (a dedicated NSCache, so the plain
// absolute path is the key — no per-probe "b|" string namespacing, and a
// cache hit allocates nothing).
- (BOOL)_newBackendPathRestricted:(NSString *)path {
    if(!path || [path length] == 0 || [path isEqualToString:@"/"] || ![path isAbsolutePath]) {
        return NO;
    }

    [store checkForChanges];

    ShadowRulesetSnapshot* snapshot = [store currentSnapshot];
    NSUInteger gen = snapshot.generation;

    NSInteger cached = [self _cachedVerdictForKey:path generation:gen cache:backendCache];

    if(cached >= 0) {
        return (BOOL)cached;
    }

    BOOL restricted = shdwSnapshotDeniesPath(snapshot, path);

    if(!restricted) {
        restricted = [self _newBackendPathRestricted:[path stringByDeletingLastPathComponent]];
    }

    [self _storeVerdict:restricted forKey:path generation:gen cache:backendCache];
    return restricted;
}
@end