#import "RestrictionEngine.h"
#import "RestrictionResolver.h"
#import "RulesetStore.h"
#import <Shadow/Core.h>
#import <Shadow/Core+Utilities.h>
#import <Shadow/Ruleset.h>
#import <Shadow/JBPath.h>

#import <limits.h>
#import <unistd.h>
#import <stdarg.h>

// THE CUTOVER FLAG (Candidate 5 differential migration).
//
// Value 0 (default): the LEGACY engine is authoritative for path queries and
// the NEW resolver-based engine runs alongside in shadow mode. Every query is
// answered by both; a divergent verdict is logged LOUDLY to stderr (write(2),
// so it survives the common.h NSLog compile-out in release builds) and the
// legacy verdict is returned. This is the plan's "keep the old path under the
// differential flag" state: production behavior is byte-for-byte the
// pre-Candidate-5 pipeline until parity is proven.
//
// Flip to 1 ONLY after the DEBUG differential and the harness
// (tests/RestrictionTests.m + tests/main.m, which builds with -DDEBUG and
// prints every mismatch) have proven parity for every query shape. The new
// engine is then THE answer for path queries; the legacy evaluator stays
// compiled (the DEBUG differential still guards it) until it is removed.
#ifndef SHADOW_NEW_ENGINE_AUTHORITATIVE
#define SHADOW_NEW_ENGINE_AUTHORITATIVE 0
#endif

// How long a cached decision is honored (see the cache notes below).
// Trimmed from 2.0s (plan C0-1): a "not restricted" verdict for a
// nonexistent path is cached, and if the jailbreak file appears within the
// window a probe gets a stale "allowed". Ruleset reloads already invalidate
// via the generation tag; this shrinks the filesystem-appearance window.
static const NSTimeInterval kShadowDecisionCacheTTL = 0.5;

// Reentrancy guard for the LEGACY engine's resolve-before-exempt step (see
// Core.m history): the libc realpath hook re-enters the engine from realpath,
// so each evaluator that calls realpath keeps its own per-thread guard. The
// NEW engine's guard lives in RestrictionResolver.m (shdw_resolver_resolving).
static _Thread_local BOOL shdw_legacy_resolving = NO;

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

// Loud divergence report. stderr via write(2): NSLog is compiled out of
// release builds (common.h) and these mismatches are exactly what must
// surface in production shadow mode.
static void shdwReportDiffMismatch(ShadowRestrictionQuery* query, BOOL legacy, BOOL fresh) {
    char buf[640];
    int n = snprintf(buf, sizeof(buf),
        "[Shadow] DIFFERENTIAL MISMATCH path=%s wd=%s legacy=%s new=%s operation=%ld flags=%lu — "
        "keeping legacy (SHADOW_NEW_ENGINE_AUTHORITATIVE=0). Do not flip the cutover until proven.\n",
        query.path ? [query.path UTF8String] : "(nil)",
        query.workingDirectory ? [query.workingDirectory UTF8String] : "(nil)",
        legacy ? "restricted" : "allowed",
        fresh ? "restricted" : "allowed",
        (long)query.operation,
        (unsigned long)query.flags);

    if(n > 0) {
        (void)write(STDERR_FILENO, buf, (size_t)n);
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
    // the old Core.m decisionCache and Backend.m cache_restricted). Entries
    // are @[computedTime, verdict, generation], honored only within
    // kShadowDecisionCacheTTL and while the generation matches.
    //   - tier 1 (top-level verdicts): key = raw query path, or @[wd, path]
    //     for the working-dir composite (same key shapes as the old
    //     decisionCache; the resolved abs path is also probed under "b|" via
    //     the tier-2 entries).
    //   - tier 2 (backend evaluation incl. parent recursion): key = @"b|" +
    //     normalized absolute path (namespaced so plain string keys can never
    //     collide), gen-checked like the old cache_restricted but with the
    //     same TTL as tier 1 — a strictly smaller staleness window than the
    //     old generation-only backend cache.
    NSCache* sharedCache;

    // The legacy engine's own caches, preserved exactly (its decisionCache
    // TTL'd 3-array; its backend cache generation-packed, no TTL). They die
    // with the differential.
    NSCache* legacyDecisionCache;
    NSCache* legacyBackendCache;
}

- (instancetype)initWithStore:(ShadowRulesetStore *)rulesetStore {
    if((self = [super init])) {
        store = rulesetStore;
        sharedCache = [NSCache new];
        [sharedCache setCountLimit:1024];
        legacyDecisionCache = [NSCache new];
        [legacyDecisionCache setCountLimit:512];
        legacyBackendCache = [NSCache new];
        [legacyBackendCache setCountLimit:1024];
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

// Differential dispatch: both engines evaluate every path query; mismatches
// are logged loudly and the verdict follows the cutover flag (legacy by
// default — see SHADOW_NEW_ENGINE_AUTHORITATIVE above).
- (BOOL)isPathRestrictedQuery:(ShadowRestrictionQuery *)query {
    @autoreleasepool {
        BOOL legacy = [self _legacyPathRestrictedQuery:query];
        BOOL fresh = [self _newPathRestrictedQuery:query];

        if(legacy != fresh && query) {
            shdwReportDiffMismatch(query, legacy, fresh);
        }

        return SHADOW_NEW_ENGINE_AUTHORITATIVE ? fresh : legacy;
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
    // ("Cydia", "SILEO") to dodge exact matches. Rulesets additionally
    // normalize their entries to lowercase at load (RulesetCompiler _compile).
    NSString* scheme_lower = [scheme lowercaseString];

    // Add some exceptions (direct compares: no per-call array allocation).
    if([scheme_lower isEqualToString:@"file"] || [scheme_lower isEqualToString:@"http"] || [scheme_lower isEqualToString:@"https"]) {
        return NO;
    }

    ShadowRulesetSnapshot* snapshot = [store currentSnapshot];

    for(RulesetEngine* ruleset in snapshot.rulesets) {
        if([ruleset isSchemeRestricted:scheme_lower]) {
            return YES;
        }
    }

    return NO;
}

// C0-3: ruleset-driven bundle-ID check (the static well-known list lives in
// -[Shadow isBundleIDRestricted:], which consults this for the user-extensible
// half). Rulesets normalize their entries to lowercase at load.
- (BOOL)isBundleIDRestricted:(NSString *)bundleID {
    if(!bundleID || [bundleID length] == 0) {
        return NO;
    }

    [store checkForChanges];

    NSString* bundleID_lower = [bundleID lowercaseString];
    ShadowRulesetSnapshot* snapshot = [store currentSnapshot];

    for(RulesetEngine* ruleset in snapshot.rulesets) {
        if([ruleset isBundleIDRestricted:bundleID_lower]) {
            return YES;
        }
    }

    return NO;
}

- (NSUInteger)rulesetGeneration {
    return [store generation];
}

// ---------------------------------------------------------------------------
// LEGACY engine (pre-Candidate-5 pipeline, preserved verbatim)
// ---------------------------------------------------------------------------

// The old -[Shadow isPathRestricted:options:] body, transcribed onto query
// fields. Kept exactly (rename-only) so the differential compares real
// production behavior.
- (BOOL)_legacyPathRestrictedQuery:(ShadowRestrictionQuery *)query {
    // Pool-less pthread_create threads (Unity/Unreal loading threads, Flutter
    // engine threads, C++ std::thread file IO) have no autoreleasepool: every
    // autoreleased object this method allocates — the composite cache key,
    // joined/standardized/resolved path strings, the query copy — would log
    // "autoreleased with no pool in place — just leaking" and never be
    // released. The pool drains them all; the BOOL return survives, and cache
    // entries (NSCache retains) and _Thread_local state outlive the pool.
    @autoreleasepool {
        shdwEnsureContext();
        NSString* path = query ? query.path : nil;

        if(!path || [path length] == 0 || [path isEqualToString:@"/"]) {
            return NO;
        }

        // Bounded decision cache: repeat queries of the same absolute path with
        // default options skip tilde expansion, NSURL canonicalization, the
        // rootless access() probe and the backend lookup. Entries carry the time
        // they were computed, the store's ruleset generation (C0-5), and the
        // restricted verdict; they are honored only within
        // kShadowDecisionCacheTTL AND while the generation matches, so a
        // changed file system (new/removed jbroot files) is observed at most
        // TTL later while a ruleset reload invalidates immediately. Options
        // that alter the decision (file extension, resolve re-check, symlink
        // resolution) are never cached; the single exception is the
        // working-dir-only query the readdir/enumerator hook lanes pass for
        // every directory entry: with nothing but the working directory set,
        // the decision depends solely on the joined workingDir+entry path, so
        // it is cached under a composite (workingDir, entry) key — an array
        // key, which can never collide with the string keys of plain
        // absolute-path queries, nor between two different (workingDir,
        // entry) pairs (identical pairs imply identical joined paths and
        // therefore identical decisions). The working dir must be absolute (a
        // relative one falls back to the process cwd, which is not a stable
        // cache input) and the entry must not be tilde-prefixed (tilde
        // expansion would make the decision depend on the process home).
        BOOL defaultQuery = (query.operation == ShadowRestrictionOperationRead)
            && (query.flags == ShadowRestrictionFlagResolve);
        BOOL cacheable = defaultQuery && (query.workingDirectory == nil) && [path isAbsolutePath];
        id cacheKey = path;

        if(!cacheable && defaultQuery && query.workingDirectory
            && [query.workingDirectory isAbsolutePath] && ![path isAbsolutePath] && ![path hasPrefix:@"~"]) {
            cacheKey = @[query.workingDirectory, path];
            cacheable = YES;
        }

        if(cacheable) {
            NSUInteger gen = [store generation];
            NSArray* cached = [legacyDecisionCache objectForKey:cacheKey];

            if(cached) {
                double age = [NSDate timeIntervalSinceReferenceDate] - [[cached objectAtIndex:0] doubleValue];

                if(age >= 0 && age <= kShadowDecisionCacheTTL
                    && [[cached objectAtIndex:2] unsignedIntegerValue] == gen) {
                    return [[cached objectAtIndex:1] boolValue];
                }
            }
        }

        // cacheKey (above) already holds the original query path/key, so the
        // remaining pipeline mutates `path` freely.
        BOOL restricted = NO;

        // Resolve any tilde paths.
        path = [path stringByExpandingTildeInPath];

        if([path characterAtIndex:0] == '~') {
            return NO;
        }

        // Attempt to resolve any relative paths.
        if(![path isAbsolutePath]) {
            NSString* cwd = query.workingDirectory;

            if(!cwd || ![cwd isAbsolutePath]) {
                cwd = [[NSFileManager defaultManager] currentDirectoryPath];
            }

            path = [cwd stringByAppendingPathComponent:path];
        }

        // Standardize path string for our checks.
        path = [Shadow getStandardizedPath:path];

        // Run checks if path is outside the app sandbox.
        BOOL shouldCheckPath = (!shdw_ctx.hasAppSandbox || (![path hasPrefix:shdw_ctx.bundlePath] && ![path hasPrefix:shdw_ctx.homePath]));

        // Resolve-before-exempt: a symlink inside the sandbox (or bundle) can
        // point at jailbreak files outside it, so a lexical prefix match against
        // homePath/bundlePath is not a safe exemption. realpath() the exempted
        // candidate and evaluate the resolved target: the restricted-root prefixes
        // are a cheap early-out, but the target also runs through the same
        // evaluation a non-exempt path would get, so a symlink at a ROOTFUL
        // restricted path (e.g. /Library/MobileSubstrate, /usr/lib/substrate,
        // /usr/bin/ssh) is restricted exactly when the equivalent direct path
        // would be. A failed resolution (path does not exist) keeps the exemption
        // — a non-existent path can't leak anything. Only no-follow queries
        // (readlink/lstat link-location checks) skip resolution: they
        // request a location-only answer about the link itself, not its target.
        BOOL noFollow = (query.flags & ShadowRestrictionFlagNoFollow) != 0;

        if(!shouldCheckPath
            && !noFollow
            && !shdw_legacy_resolving) {
            shdw_legacy_resolving = YES;

            char resolved_path[PATH_MAX];
            BOOL resolvedRestricted = NO;

            if(realpath([path fileSystemRepresentation], resolved_path)) {
                NSString* resolved = [NSString stringWithUTF8String:resolved_path];

                resolvedRestricted = shdwIsPathInRestrictedRoot(resolved)
                    || [self _legacyEvaluatePathRestriction:resolved query:query];
            }

            shdw_legacy_resolving = NO;

            if(resolvedRestricted) {
                restricted = YES;
                goto done;
            }
        }

        if(shouldCheckPath) {
            if([self _legacyEvaluatePathRestriction:path query:query]) {
                restricted = YES;
                goto done;
            }
        }

        // Resolve into full path and check again.
        if(query.flags & ShadowRestrictionFlagResolve) {
            NSString* resolved_path = [path stringByStandardizingPath];

            if(![resolved_path isEqualToString:path]) {
                ShadowRestrictionQuery* sub = [ShadowRestrictionQuery queryWithPath:resolved_path];
                sub.workingDirectory = query.workingDirectory;
                sub.operation = query.operation;
                sub.flags = query.flags & ~ShadowRestrictionFlagResolve;

                if([self _legacyPathRestrictedQuery:sub]) {
                    restricted = YES;
                    goto done;
                }
            }
        }

        done:
        if(cacheable) {
            // C0-5: generation tag — a ruleset reload invalidates the entry at
            // the next query even inside the TTL window.
            [legacyDecisionCache setObject:@[@([NSDate timeIntervalSinceReferenceDate]), @(restricted), @([store generation])] forKey:cacheKey];
        }

        return restricted;
    }
}

// The old -[Shadow evaluatePathRestriction:options:] body, transcribed onto
// query fields (rename-only move from Core.m).
- (BOOL)_legacyEvaluatePathRestriction:(NSString *)path query:(ShadowRestrictionQuery *)query {
    // C0-1: write/create/delete probes must not be let through by the
    // existence gates — a detector probing a restricted-classified path it
    // could create (e.g. /var/jb/usr/lib/libjailbreak.dylib before it
    // exists) must get a denial, not an "allowed because absent".
    BOOL isWrite = (query.operation == ShadowRestrictionOperationWrite);

    // Rootless optimization: skip rooted checks. Covers /var/jb, its
    // canonical preboot target and /cores/ via shdwIsPathInRestrictedRoot.
    if(shdw_ctx.rootless) {
        if(shdwIsPathInRestrictedRoot(path)) {
            return YES;
        }

        BOOL checkable = [path hasPrefix:@"/var"]
            || [path hasPrefix:@"/private/preboot"]
            || [path hasPrefix:@"/usr/lib"];

        if(!checkable) {
            // Rooted-flavored query on a rootless jailbreak: the jailbreak file,
            // if it exists, lives under /var/jb + path. Only evaluate rulesets
            // (against the canonical rooted-flavored path, so existing ruleset
            // entries/predicates apply) if the concrete jbroot file exists.
            // Write probes skip the existence gate (C0-1): the ruleset decides
            // even for a not-yet-created target.
            if(!isWrite) {
                NSString* jbpath = [@"/var/jb" stringByAppendingString:path];
                int errno_old = errno;
                BOOL exists = (access([jbpath fileSystemRepresentation], F_OK) == 0);
                errno = errno_old;

                if(!exists) {
                    return NO;
                }
            }

            if([self _legacyBackendPathRestricted:path]) {
                NSLog(@"[Shadow] isPathRestricted: restricted path: %@", path);
                return YES;
            }

            return NO;
        }
    }

    if([path hasPrefix:@"/usr/lib"]) {
        // Skip checks if file doesn't exist. Write probes skip the gate
        // (C0-1): a restricted-classified path is denied even when absent.
        if(!isWrite) {
            int errno_old = errno;
            NSString* check_path = path;

            if(shdw_ctx.rootless) {
                check_path = [@"/var/jb" stringByAppendingString:path];
            }

            if(access([check_path fileSystemRepresentation], F_OK) != 0) {
                // reset errno
                errno = errno_old;
                return NO;
            }
        }
    }

    if([self _legacyBackendPathRestricted:path]) {
        NSLog(@"[Shadow] isPathRestricted: restricted path: %@", path);
        return YES;
    }

    return NO;
}

// The old -[ShadowBackend isPathRestricted:] body (rename-only move from
// Backend.m): its own generation-packed cache (no TTL, exactly as before) and
// the store snapshot for the ruleset passes + parent recursion.
- (BOOL)_legacyBackendPathRestricted:(NSString *)path {
    if(!path || [path length] == 0 || [path isEqualToString:@"/"] || ![path isAbsolutePath]) {
        return NO;
    }

    [store checkForChanges];

    ShadowRulesetSnapshot* snapshot = [store currentSnapshot];
    NSUInteger gen = snapshot.generation;

    // Entries are packed NSNumbers, as in the old Backend.m cache.
    NSNumber* cached = (NSNumber *)[legacyBackendCache objectForKey:path];

    if(cached) {
        // Packed as (generation << 1) | restricted: one NSNumber per entry
        // instead of a 2-element array, with identical generation invalidation.
        unsigned long long v = [cached unsignedLongLongValue];

        if((NSUInteger)(v >> 1) == gen) {
            return (v & 1) != 0;
        }
    }

    // pass 1: compliance (hard veto)
    for(RulesetEngine* ruleset in snapshot.rulesets) {
        if(![ruleset isPathCompliant:path]) {
            [legacyBackendCache setObject:(NSArray *)(id)@(((unsigned long long)gen << 1) | 1) forKey:path];
            return YES;
        }
    }

    // pass 2: whitelist
    BOOL whitelisted = NO;

    for(RulesetEngine* ruleset in snapshot.rulesets) {
        if([ruleset isPathWhitelisted:path]) {
            whitelisted = YES;
            break;
        }
    }

    // pass 3: blacklist
    BOOL blacklisted = NO;

    for(RulesetEngine* ruleset in snapshot.rulesets) {
        if([ruleset isPathBlacklisted:path]) {
            blacklisted = YES;
            break;
        }
    }

    BOOL restricted = blacklisted && !whitelisted;

    if(!restricted) {
        restricted = [self _legacyBackendPathRestricted:[path stringByDeletingLastPathComponent]];
    }

    [legacyBackendCache setObject:(NSArray *)(id)@(((unsigned long long)gen << 1) | (restricted ? 1 : 0)) forKey:path];
    return restricted;
}

// ---------------------------------------------------------------------------
// NEW engine (resolver + snapshot evaluation + single cache)
// ---------------------------------------------------------------------------

// Single-cache probe: nil = miss (or stale), else the cached verdict. Both
// tiers use the same @[time, verdict, generation] entry shape.
- (NSNumber *)_cachedVerdictForKey:(id)key generation:(NSUInteger)gen {
    NSArray* cached = [sharedCache objectForKey:key];

    if(cached) {
        double age = [NSDate timeIntervalSinceReferenceDate] - [[cached objectAtIndex:0] doubleValue];

        if(age >= 0 && age <= kShadowDecisionCacheTTL
            && [[cached objectAtIndex:2] unsignedIntegerValue] == gen) {
            return [cached objectAtIndex:1];
        }
    }

    return nil;
}

- (void)_storeVerdict:(BOOL)verdict forKey:(id)key generation:(NSUInteger)gen {
    [sharedCache setObject:@[@([NSDate timeIntervalSinceReferenceDate]), @(verdict), @(gen)] forKey:key];
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
        // raw path; working-dir-only queries under the (wd, path) composite.
        BOOL defaultQuery = (query.operation == ShadowRestrictionOperationRead)
            && (query.flags == ShadowRestrictionFlagResolve);
        BOOL cacheable = defaultQuery && (query.workingDirectory == nil) && [path isAbsolutePath];
        id cacheKey = path;

        if(!cacheable && defaultQuery && query.workingDirectory
            && [query.workingDirectory isAbsolutePath] && ![path isAbsolutePath] && ![path hasPrefix:@"~"]) {
            cacheKey = @[query.workingDirectory, path];
            cacheable = YES;
        }

        if(cacheable) {
            NSNumber* cached = [self _cachedVerdictForKey:cacheKey generation:[store generation]];

            if(cached) {
                return [cached boolValue];
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
            [self _storeVerdict:restricted forKey:cacheKey generation:[store generation]];
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
// recursion, all behind the single cache (tier-2 keys namespaced "b|" so they
// can never collide with tier-1 string keys).
- (BOOL)_newBackendPathRestricted:(NSString *)path {
    if(!path || [path length] == 0 || [path isEqualToString:@"/"] || ![path isAbsolutePath]) {
        return NO;
    }

    [store checkForChanges];

    ShadowRulesetSnapshot* snapshot = [store currentSnapshot];
    NSUInteger gen = snapshot.generation;
    NSString* cacheKey = [@"b|" stringByAppendingString:path];

    NSNumber* cached = [self _cachedVerdictForKey:cacheKey generation:gen];

    if(cached) {
        return [cached boolValue];
    }

    BOOL restricted = shdwSnapshotDeniesPath(snapshot, path);

    if(!restricted) {
        restricted = [self _newBackendPathRestricted:[path stringByDeletingLastPathComponent]];
    }

    [self _storeVerdict:restricted forKey:cacheKey generation:gen];
    return restricted;
}
@end