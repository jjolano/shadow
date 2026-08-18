#import "RestrictionEngine.h"
#import "RulesetStore.h"
#import <Shadow/Core.h>
#import <Shadow/Core+Utilities.h>
#import "Ruleset.h"
#import <Shadow/JBPath.h>

#import <limits.h>
#import <unistd.h>
#import <dlfcn.h>
#import <string.h>

// Ponytail: central strict enforce via dlsym + TLS guard (no PseudoSandboxPolicy header import)
static _Thread_local BOOL _inPseudoEval = NO;

static BOOL shdwPseudoShouldDeny(const char *cpath) {
    if(!cpath || !cpath[0]) return NO;
    if(_inPseudoEval) return NO;
#ifndef SHADOW_TEST_HARNESS
    static BOOL (*fn)(const char*) = NULL;
    static BOOL didLookup = NO;
    if(!didLookup) {
        didLookup = YES;
        fn = dlsym(RTLD_DEFAULT, "shdw_pseudo_should_deny");
        if(!fn) fn = dlsym(RTLD_DEFAULT, "shdw_pseudo_enforce_should_deny");
        if(!fn) fn = dlsym(RTLD_DEFAULT, "shdwPseudoEnforceShouldDeny");
        if(!fn) fn = dlsym(RTLD_DEFAULT, "shdw_pseudo_denies_path");
        if(!fn) fn = dlsym(RTLD_DEFAULT, "shdw_pseudo_is_restricted");
    }
    if(!fn) return NO;
    _inPseudoEval = YES;
    BOOL r = fn(cpath);
    _inPseudoEval = NO;
    return r;
#else
    return NO;
#endif
}

// How long a cached decision is honored (see the cache notes below).
// Trimmed from 2.0s (plan C0-1): a "not restricted" verdict for a
// nonexistent path is cached, and if the jailbreak file appears within the
// window a probe gets a stale "allowed". Ruleset reloads already invalidate
// via the generation tag; this shrinks the filesystem-appearance window.
static const NSTimeInterval kShadowDecisionCacheTTL = 0.5;

// Restricted roots single source via JBPath (shdw_is_restricted_root).
static BOOL shdwIsPathInRestrictedRoot(NSString* path) {
    return path ? shdw_is_path_in_restricted_root(path) : NO;
}

// realpath is hooked and can re-enter this engine on the same thread.
static _Thread_local BOOL shdw_resolving = NO;

static NSString* shdwExpandTilde(NSString* path) {
    path = [path stringByExpandingTildeInPath];
    return [path characterAtIndex:0] == '~' ? nil : path;
}

static NSString* shdwJoinWorkingDirectory(NSString* path, NSString* wd) {
    if(!wd || ![wd isAbsolutePath]) {
        wd = [[NSFileManager defaultManager] currentDirectoryPath];
    }

    return [wd stringByAppendingPathComponent:path];
}

static BOOL shdwIsSandboxExempt(ShadowRestrictionContext context, NSString* path) {
    if(!context.hasAppSandbox) return NO;
    if([path hasPrefix:context.bundlePath] || [path hasPrefix:context.homePath]) return YES;
    for(NSString *gc in context.groupContainerPaths) {
        if(gc && [path hasPrefix:gc]) return YES;
    }
    return NO;
}

// Group containers: exempt when inside any group container (central strict enforce helper)
static BOOL shdwIsSandboxExemptGroup(ShadowRestrictionContext context, NSString* path) {
    if(!context.hasAppSandbox) return NO;
    for(NSString *gc in context.groupContainerPaths) {
        if(gc && [path hasPrefix:gc]) return YES;
    }
    return NO;
}
static BOOL shdwIsGroupContainerPath(ShadowRestrictionContext context, NSString* path) {
    return shdwIsSandboxExemptGroup(context, path);
}

static NSString* shdwResolveTarget(NSString* path) {
    if(shdw_resolving) {
        return nil;
    }

    shdw_resolving = YES;
    char resolved[PATH_MAX];
    BOOL ok = realpath([path fileSystemRepresentation], resolved) != NULL;
    shdw_resolving = NO;
    return ok ? [NSString stringWithUTF8String:resolved] : nil;
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
    ShadowRestrictionContext _context;

    // One generation-aware decision cache split by responsibility:
    //   - sharedCache (tier 1, top-level verdicts): key = raw query path, or
    //     a length-prefixed joined workingDir+entry string for the
    //     working-dir composite (same key shapes as the old decisionCache;
    //     the resolved abs path is also probed under the tier-2 entries).
    //   - rulesetCache (tier 2, ruleset evaluation incl. parent recursion):
    //     key = plain normalized absolute path, gen-checked like the old
    //     cache_restricted but with the same TTL as tier 1 — a strictly
    //     smaller staleness window than the old generation-only backend
    //     cache.
    // Entries are @[computedTime, packed(generation << 1 | verdict)] (one
    // NSNumber instead of two) and are honored only within
    // kShadowDecisionCacheTTL and while the generation matches.
    NSCache* sharedCache;
    NSCache* rulesetCache;
}

- (instancetype)initWithContext:(ShadowRestrictionContext)context {
    if((self = [super init])) {
        _context = context;
        store = [ShadowRulesetStore new];
        sharedCache = [NSCache new];
        [sharedCache setCountLimit:1024];
        rulesetCache = [NSCache new];
        [rulesetCache setCountLimit:1024];
    }

    return self;
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

- (BOOL)isPathRestrictedQuery:(ShadowRestrictionQuery *)query {
    @autoreleasepool {
        return [self _pathRestrictedQuery:query];
    }
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

// Top-level pipeline: resolution stages (tilde, working-dir join,
// standardization, sandbox exemption, resolve-before-exempt alias, no-follow)
// feeding the new evaluation; structurally identical to the legacy flow so
// the differential's only degrees of freedom are the resolution helpers and
// the cache.
- (BOOL)_pathRestrictedQuery:(ShadowRestrictionQuery *)query {
    @autoreleasepool {
        if(!query) {
            return NO;
        }

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
        NSString* expanded = nil;

        // Central strict enforce: before tilde/workdir, check raw craw (+ joined form for relative)
        // Harness-safe via dlsym + _inPseudoEval TLS guard; stdRaw exempt group containers.
        {
            NSString *craw = path;
            if(!_inPseudoEval && craw) {
                BOOL isRel = ![craw isAbsolutePath] && ![craw hasPrefix:@"~"];
                BOOL crawExempt = shdwIsGroupContainerPath(_context, craw);
                if(!crawExempt) {
                    const char *ccraw = [craw fileSystemRepresentation];
                    if(ccraw && shdwPseudoShouldDeny(ccraw)) { restricted = YES; goto done; }
                    if(isRel) {
                        NSString *joinedRaw = shdwJoinWorkingDirectory(craw, query.workingDirectory);
                        joinedRaw = [Shadow getStandardizedPath:joinedRaw];
                        if(!shdwIsGroupContainerPath(_context, joinedRaw)) {
                            const char *cj = [joinedRaw fileSystemRepresentation];
                            if(cj && shdwPseudoShouldDeny(cj)) { restricted = YES; goto done; }
                        }
                    }
                }
            }
        }

        // Tilde: deny on unresolvable user; expand otherwise.
        expanded = shdwExpandTilde(path);

        if(!expanded) {
            return NO;
        }

        path = expanded;

        // Relative paths join the working directory (or process cwd).
        if(![path isAbsolutePath]) {
            path = shdwJoinWorkingDirectory(path, query.workingDirectory);
        }

        // Standardize.
        path = [Shadow getStandardizedPath:path];

        // Run checks if path is outside the app sandbox.
        BOOL shouldCheckPath = !shdwIsSandboxExempt(_context, path);

        // Resolve-before-exempt. shdwResolveTarget owns the per-thread
        // realpath guard, so no check is needed here.
        BOOL noFollow = (query.flags & ShadowRestrictionFlagNoFollow) != 0;

        if(!shouldCheckPath && !noFollow) {
            NSString* resolved = shdwResolveTarget(path);

            if(resolved) {
                BOOL resolvedRestricted = shdwIsPathInRestrictedRoot(resolved)
                    || [self _evaluatePathRestriction:resolved query:query];

                if(resolvedRestricted) {
                    restricted = YES;
                    goto done;
                }
            }
        }

        if(shouldCheckPath) {
            if([self _evaluatePathRestriction:path query:query]) {
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

                if([self _pathRestrictedQuery:sub]) {
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

// Rootless fast-paths and existence gates before ruleset evaluation.
- (BOOL)_evaluatePathRestriction:(NSString *)path query:(ShadowRestrictionQuery *)query {
    BOOL isWrite = (query.operation == ShadowRestrictionOperationWrite);

    if(_context.rootless) {
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

            if([self _rulesetDeniesPath:path]) {
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

            if(_context.rootless) {
                check_path = [@"/var/jb" stringByAppendingString:path];
            }

            if(access([check_path fileSystemRepresentation], F_OK) != 0) {
                errno = errno_old;
                return NO;
            }
        }
    }

    if([self _rulesetDeniesPath:path]) {
        NSLog(@"[Shadow] isPathRestricted: restricted path: %@", path);
        return YES;
    }

    return NO;
}

// Ruleset passes and parent recursion behind the tier-2 cache.
- (BOOL)_rulesetDeniesPath:(NSString *)path {
    if(!path || [path length] == 0 || [path isEqualToString:@"/"] || ![path isAbsolutePath]) {
        return NO;
    }

    [store checkForChanges];

    ShadowRulesetSnapshot* snapshot = [store currentSnapshot];
    NSUInteger gen = snapshot.generation;

    NSInteger cached = [self _cachedVerdictForKey:path generation:gen cache:rulesetCache];

    if(cached >= 0) {
        return (BOOL)cached;
    }

    BOOL restricted = shdwSnapshotDeniesPath(snapshot, path);

    if(!restricted) {
        restricted = [self _rulesetDeniesPath:[path stringByDeletingLastPathComponent]];
    }

    [self _storeVerdict:restricted forKey:path generation:gen cache:rulesetCache];
    return restricted;
}
@end
