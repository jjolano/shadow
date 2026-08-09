#import <Shadow/Core.h>
#import <Shadow/Core+Utilities.h>
#import <Shadow/Backend.h>
#import <Shadow/JBPath.h>

#import <dlfcn.h>
#import <pwd.h>
#import <stdlib.h>

#import "../vendor/apple/dyld_priv.h"
#import "../common.h"

// Bounded decision cache for -[Shadow isPathRestricted:options:].
static NSCache* decisionCache;

// How long a cached decision is honored (see isPathRestricted:options:).
// Trimmed from 2.0s (plan C0-1): a "not restricted" verdict for a
// nonexistent path is cached, and if the jailbreak file appears within the
// window a probe gets a stale "allowed". Ruleset reloads already invalidate
// via the generation tag; this shrinks the filesystem-appearance window.
static const NSTimeInterval kDecisionCacheTTL = 0.5;

// Reentrancy guard for the resolve-before-exempt step: the libc realpath hook
// (hooks/libc.x) re-enters isCPathRestricted from realpath — this code calls
// realpath from inside isPathRestricted, so without a per-thread guard the
// hook → isPathRestricted → realpath → hook cycle would recurse forever.
// _Thread_local is exactly right: the only recursion is same-thread.
static _Thread_local BOOL shdw_resolvingPath = NO;

// C0-2: Shadow-internal read scope flag. Shadow-owned code wraps its own
// filesystem reads in SHADOW_INTERNAL_SCOPE (see Core.h) so the tweak's own
// hooks never filter them. A depth counter (not a BOOL) so nested scopes —
// e.g. Backend._checkRulesetChanges → _reloadRulesets → _loadRulesets —
// stay busy until the outermost scope exits. Exposed to the dylib hook layer
// through the exported class methods in @implementation Shadow below;
// _Thread_local because scopes are strictly same-thread (the hook that reads
// the flag runs on the thread that entered the scope).
static _Thread_local NSUInteger shdw_internal_busy = 0;

// Restricted roots that never hold legitimate app data: the rootless /var/jb
// fast-path, its canonical target (/var/jb is a symlink to
// /private/preboot/<hash>/jb on rootless) and rooted /cores crash dumps.
// On roothide there is no /var/jb at all — the jailbreak root is a
// random-named jbroot resolved through jbroot() — so that prefix check is
// replaced by a live-jbroot check.
static BOOL isPathInRestrictedRoot(NSString* path) {
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

@implementation Shadow
@synthesize bundlePath, homePath, realHomePath, hasAppSandbox, rootless;

+ (void)load {
    decisionCache = [NSCache new];
    [decisionCache setCountLimit:512];
}

+ (void)shdwEnterInternalRead {
    shdw_internal_busy += 1;
}

+ (void)shdwExitInternalRead {
    if(shdw_internal_busy > 0) {
        shdw_internal_busy -= 1;
    }
}

+ (BOOL)shdwIsInternalRead {
    return shdw_internal_busy > 0;
}

- (instancetype)init {
    if((self = [super init])) {
        bundlePath = [[[self class] getExecutablePath] stringByDeletingLastPathComponent];
        homePath = NSHomeDirectory();

        // getpwuid can return NULL (no passwd entry / unreadable database in a
        // sandboxed context); dereferencing it crashes every app that loads
        // Shadow. Fall back to NSHomeDirectory().
        struct passwd* pw = getpwuid(getuid());
        realHomePath = (pw && pw->pw_dir) ? @(pw->pw_dir) : homePath;

        bundlePath = [[self class] getStandardizedPath:bundlePath];
        homePath = [[self class] getStandardizedPath:homePath];
        realHomePath = [[self class] getStandardizedPath:realHomePath];

        hasAppSandbox = [[bundlePath pathExtension] isEqualToString:@"app"];
        rootless = JBIsRootless();

        backend = [ShadowBackend new];
    }

    return self;
}

+ (instancetype)sharedInstance {
    static Shadow* sharedInstance = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        sharedInstance = [self new];
    });

    return sharedInstance;
}

- (BOOL)isAddrRestricted:(const void *)addr {
    if(addr) {
        // See if this address belongs to a restricted file.
        const char* image_path = dyld_image_path_containing_address(addr);
        return [self isCPathRestricted:image_path];
    }

    return NO;
}

- (BOOL)isCPathRestricted:(const char *)path {
    if(!path || !path[0]) {
        return NO;
    }

    // C fast-path: the restricted roots are exact prefix checks (the
    // /private/preboot prefix also covers the resolved rootless jbroot
    // target). Every hooked open/stat/access hits this; detector probes of
    // these roots skip the NSString alloc + full pipeline.
    if(strncmp(path, "/var/jb", 7) == 0
        || strncmp(path, "/cores/", 7) == 0
        || strncmp(path, "/private/preboot", 16) == 0) {
        return YES;
    }

    // Pool-less pthread_create threads (see isPathRestricted:options:):
    // [NSString stringWithUTF8String:] here is autoreleased, and the libc
    // hooks call this for every open/stat/access/lstat/readdir entry.
    @autoreleasepool {
        return [self isPathRestricted:[NSString stringWithUTF8String:path]];
    }
}

- (BOOL)isPathRestricted:(NSString *)path {
    return [self isPathRestricted:path options:nil];
}

// Evaluate an absolute, standardized path exactly as a non-exempt
// (shouldCheckPath == YES) query would be: rootless fast-paths, existence
// gates, then the backend ruleset. Shared by the direct check and the
// resolve-before-exempt re-check so a resolved symlink target is restricted
// exactly when the equivalent direct path would be. options only contributes
// the operation intent, same as the direct path.
- (BOOL)evaluatePathRestriction:(NSString *)path options:(NSDictionary<NSString *, id> *)options {
    // C0-1: write/create/delete probes must not be let through by the
    // existence gates — a detector probing a restricted-classified path it
    // could create (e.g. /var/jb/usr/lib/libjailbreak.dylib before it
    // exists) must get a denial, not an "allowed because absent".
    BOOL isWrite = [[options objectForKey:kShadowRestrictionOperation] isEqualToString:kShadowRestrictionOpWrite];

    // Rootless optimization: skip rooted checks. Covers /var/jb, its
    // canonical preboot target and /cores/ via isPathInRestrictedRoot.
    if(rootless) {
        if(isPathInRestrictedRoot(path)) {
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

            if([backend isPathRestricted:path]) {
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

            if(rootless) {
                check_path = [@"/var/jb" stringByAppendingString:path];
            }

            if(access([check_path fileSystemRepresentation], F_OK) != 0) {
                // reset errno
                errno = errno_old;
                return NO;
            }
        }
    }

    if([backend isPathRestricted:path]) {
        NSLog(@"[Shadow] isPathRestricted: restricted path: %@", path);
        return YES;
    }

    return NO;
}

- (BOOL)isPathRestricted:(NSString *)path options:(NSDictionary<NSString *, id> *)options {
    // Pool-less pthread_create threads (Unity/Unreal loading threads, Flutter
    // engine threads, C++ std::thread file IO) have no autoreleasepool: every
    // autoreleased object this method allocates — the composite cache key,
    // joined/standardized/resolved path strings, the options copy — would log
    // "autoreleased with no pool in place — just leaking" and never be
    // released. The pool drains them all; the BOOL return survives, and cache
    // entries (NSCache retains) and _Thread_local state outlive the pool.
    @autoreleasepool {
        if(!path || [path length] == 0 || [path isEqualToString:@"/"]) {
            return NO;
        }

        // Bounded decision cache: repeat queries of the same absolute path with
        // default options skip tilde expansion, NSURL canonicalization, the
        // rootless access() probe and the backend lookup. Entries carry the time
        // they were computed, the backend's ruleset generation (C0-5), and the
        // restricted verdict; they are honored only within kDecisionCacheTTL AND
        // while the generation matches, so a changed file system (new/removed
        // jbroot files) is observed at most TTL later while a ruleset reload
        // invalidates immediately. Options that alter the decision (file
        // extension, resolve re-check, symlink resolution) are never cached; the
        // single exception is the working-dir-only dict the readdir/enumerator
        // hook lanes pass for every directory entry: with nothing but
        // kShadowRestrictionWorkingDir in options, the decision depends solely
        // on the joined workingDir+entry path, so it is cached under a composite
        // (workingDir, entry) key — an array key, which can never collide with
        // the string keys of plain absolute-path queries, nor between two
        // different (workingDir, entry) pairs (identical pairs imply identical
        // joined paths and therefore identical decisions). The working dir must
        // be absolute (a relative one falls back to the process cwd, which is
        // not a stable cache input) and the entry must not be tilde-prefixed
        // (tilde expansion would make the decision depend on the process home).
        BOOL cacheable = ((options == nil) || ([options count] == 0)) && [path isAbsolutePath];
        id cacheKey = path;

        if(!cacheable && [options count] == 1) {
            NSString* workingDir = [options objectForKey:kShadowRestrictionWorkingDir];

            if(workingDir && [workingDir isAbsolutePath] && ![path isAbsolutePath] && ![path hasPrefix:@"~"]) {
                cacheKey = @[workingDir, path];
                cacheable = YES;
            }
        }

        if(cacheable) {
            NSUInteger gen = [backend rulesetGeneration];
            NSArray* cached = [decisionCache objectForKey:cacheKey];

            if(cached) {
                double age = [NSDate timeIntervalSinceReferenceDate] - [[cached objectAtIndex:0] doubleValue];

                if(age >= 0 && age <= kDecisionCacheTTL
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
            NSString* cwd = [options objectForKey:kShadowRestrictionWorkingDir];

            if(!cwd || ![cwd isAbsolutePath]) {
                cwd = [[NSFileManager defaultManager] currentDirectoryPath];
            }

            path = [cwd stringByAppendingPathComponent:path];
        }

        // Standardize path string for our checks.
        path = [[self class] getStandardizedPath:path];

        // Run checks if path is outside the app sandbox.
        BOOL shouldCheckPath = (!hasAppSandbox || (![path hasPrefix:bundlePath] && ![path hasPrefix:homePath]));

        // Resolve-before-exempt: a symlink inside the sandbox (or bundle) can
        // point at jailbreak files outside it, so a lexical prefix match against
        // homePath/bundlePath is not a safe exemption. realpath() the exempted
        // candidate and evaluate the resolved target: the restricted-root prefixes
        // are a cheap early-out, but the target also runs through the same
        // evaluation a non-exempt path would get, so a symlink at a ROOTFUL
        // restricted path (e.g. /Library/MobileSubstrate, /usr/lib/substrate,
        // /usr/bin/ssh) is restricted exactly when the equivalent direct path
        // would be. A failed resolution (path does not exist) keeps the exemption
        // — a non-existent path can't leak anything. Only no-follow options
        // (readlink/lstat link-location checks — the libc lane wires
        // kShadowRestrictionNoFollow into those hooks) skip resolution: they
        // request a location-only answer about the link itself, not its target.
        // Every other options-bearing query resolves too — the options only
        // contribute the working dir, relative-path handling and the
        // file-extension suffix, all already applied to `path` above, so the
        // resolved target is evaluated with the same options a direct path gets.
        // Cacheable queries fold the result into the bounded decision cache
        // (same TTL), amortizing the realpath syscall. shdw_resolvingPath
        // guards the realpath call: the libc realpath hook re-enters
        // isCPathRestricted from inside realpath, which would recurse forever
        // without the per-thread guard.
        BOOL noFollow = [[options objectForKey:kShadowRestrictionNoFollow] boolValue];

        if(!shouldCheckPath
            && !noFollow
            && !shdw_resolvingPath) {
            shdw_resolvingPath = YES;

            char resolved_path[PATH_MAX];
            BOOL resolvedRestricted = NO;

            if(realpath([path fileSystemRepresentation], resolved_path)) {
                NSString* resolved = [NSString stringWithUTF8String:resolved_path];

                resolvedRestricted = isPathInRestrictedRoot(resolved)
                    || [self evaluatePathRestriction:resolved options:options];
            }

            shdw_resolvingPath = NO;

            if(resolvedRestricted) {
                restricted = YES;
                goto done;
            }
        }

        if(shouldCheckPath) {
            if([self evaluatePathRestriction:path options:options]) {
                restricted = YES;
                goto done;
            }
        }

        // Resolve into full path and check again.
        if(![options objectForKey:kShadowRestrictionEnableResolve] || [[options objectForKey:kShadowRestrictionEnableResolve] boolValue]) {
            NSString* resolved_path = [path stringByStandardizingPath];

            if(![resolved_path isEqualToString:path]) {
                NSMutableDictionary* opt = [NSMutableDictionary dictionaryWithDictionary:options];
                [opt setObject:@(NO) forKey:kShadowRestrictionEnableResolve];

                if([self isPathRestricted:resolved_path options:[opt copy]]) {
                    restricted = YES;
                    goto done;
                }
            }
        }

        done:
        if(cacheable) {
            // C0-5: generation tag — a ruleset reload invalidates the entry at
            // the next query even inside the TTL window.
            [decisionCache setObject:@[@([NSDate timeIntervalSinceReferenceDate]), @(restricted), @([backend rulesetGeneration])] forKey:cacheKey];
        }

        return restricted;
    }
}

- (BOOL)isURLRestricted:(NSURL *)url {
    return [self isURLRestricted:url options:nil];
}

- (BOOL)isURLRestricted:(NSURL *)url options:(NSDictionary<NSString *, id> *)options {
    // Pool-less pthread_create threads (see isPathRestricted:options:): the
    // NSURL hooks (NSArray/NSBundle/LSApplicationWorkspace) call this
    // directly and [url path]/[surl path]/[url scheme] are autoreleased.
    @autoreleasepool {
        if(!url) {
            return NO;
        }

        if([url isFileURL]) {
            NSString *path = [url path];

            if([url isFileReferenceURL]) {
                NSURL *surl = [url filePathURL];

                if(surl) {
                    path = [surl path];
                }
            }

            return [self isPathRestricted:path options:options];
        }

        return [self isSchemeRestricted:[url scheme]];
    }
}

- (BOOL)isSchemeRestricted:(NSString *)scheme {
    // Backend's check allocates (lowercaseString) inside this call, and the
    // URL-scheme hooks call this directly on possibly pool-less threads.
    @autoreleasepool {
        return [backend isSchemeRestricted:scheme];
    }
}

// C0-3: hidden-app predicate. Static list of well-known package managers and
// jailbreak loaders (case-insensitive; the app-facing surface — LSApplication
// results, openURL, canOpenURL — filters these so a detector can't proxy
// through them), OR any ruleset's BlacklistBundleIDs for user extension.
- (BOOL)isBundleIDRestricted:(NSString *)bundleID {
    // Same pool-less-thread guard as isCPathRestricted: (the LSApplication
    // hooks call this per result and [bundleID lowercaseString] is
    // autoreleased).
    @autoreleasepool {
        if(!bundleID || [bundleID length] == 0) {
            return NO;
        }

        static NSSet* staticBundleIDs = nil;
        static dispatch_once_t onceToken = 0;

        dispatch_once(&onceToken, ^{
            staticBundleIDs = [NSSet setWithArray:@[
                @"com.saurik.cydia",
                @"org.coolstar.sileo",
                @"xyz.willy.zebra",
                @"com.opa334.jailbreak",       // Dopamine
                @"science.xnu.underscore",     // palera1n
                @"com.llsc12.palera1nloader",
                @"com.samiiau.loader",         // jailbreak.app
                @"jp.r333d.taurine",
                @"com.undecimus.unc0ver",
                @"eu.taurine.taurine",
                @"com.apt.theos"
            ]];
        });

        if([staticBundleIDs containsObject:[bundleID lowercaseString]]) {
            return YES;
        }

        return [backend isBundleIDRestricted:bundleID];
    }
}

// C0-3: protected-name policy. A single exact-name predicate for the
// dyld/objc/NSBundle/UIImage layers: restricted by ruleset, or one of
// Shadow's own artifacts matched by case-insensitive basename prefix
// (rootful /Library/Frameworks and rootless /var/jb prefixes both reduce to
// the same basename). "substrate"/"substitute"/"ellekit" also match their
// lib-prefixed dylibs (libsubstrate.dylib etc.).
- (BOOL)isProtectedImagePath:(NSString *)path {
    // Same pool-less-thread guard as isCPathRestricted: (the dyld/objc
    // image-load hooks call this per image; lastPathComponent/lowercaseString
    // are autoreleased).
    @autoreleasepool {
        if(!path || [path length] == 0) {
            return NO;
        }

        if([self isCPathRestricted:[path fileSystemRepresentation]]) {
            return YES;
        }

        static NSSet* protectedNames = nil;
        static dispatch_once_t onceToken = 0;

        dispatch_once(&onceToken, ^{
            protectedNames = [NSSet setWithArray:@[
                @"shadow.dylib",
                @"shadowcore",
                @"shadow.framework",
                @"libsandy.dylib",
                @"hookkit.framework",
                @"rootbridge.framework",
                @"substrate",
                @"libsubstrate",
                @"substitute",
                @"libsubstitute",
                @"ellekit",
                @"libellekit"
            ]];
        });

        NSString* basename = [[path lastPathComponent] lowercaseString];

        for(NSString* name in protectedNames) {
            if([basename hasPrefix:name]) {
                return YES;
            }
        }

        return NO;
    }
}
@end
