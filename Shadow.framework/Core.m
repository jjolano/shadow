#import <Shadow/Core.h>
#import <Shadow/Core+Utilities.h>
#import <Shadow/Backend.h>
#import <RootBridge.h>

#import <dlfcn.h>
#import <pwd.h>
#import <stdlib.h>

#import "../vendor/apple/dyld_priv.h"
#import "../common.h"

// Bounded decision cache for -[Shadow isPathRestricted:options:].
static NSCache* decisionCache;

// How long a cached decision is honored (see isPathRestricted:options:).
static const NSTimeInterval kDecisionCacheTTL = 2.0;

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
static BOOL isPathInRestrictedRoot(NSString* path) {
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
        realHomePath = @(getpwuid(getuid())->pw_dir);

        bundlePath = [[self class] getStandardizedPath:bundlePath];
        homePath = [[self class] getStandardizedPath:homePath];
        realHomePath = [[self class] getStandardizedPath:realHomePath];

        hasAppSandbox = [[bundlePath pathExtension] isEqualToString:@"app"];
        rootless = [RootBridge isJBRootless];

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

- (BOOL)isAddrExternal:(const void *)addr {
    if(addr) {
        const char* image_path = dyld_image_path_containing_address(addr);

        if(image_path) {
            if(strstr(image_path, [bundlePath fileSystemRepresentation]) != NULL) {
                return NO;
            }

            return YES;
        }
    }

    return NO;
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
    if(path) {
        return [self isPathRestricted:[NSString stringWithUTF8String:path]];
    }

    return NO;
}

- (BOOL)isPathRestricted:(NSString *)path {
    return [self isPathRestricted:path options:nil];
}

// Evaluate an absolute, standardized path exactly as a non-exempt
// (shouldCheckPath == YES) query would be: rootless fast-paths, existence
// gates, then the backend ruleset. Shared by the direct check and the
// resolve-before-exempt re-check so a resolved symlink target is restricted
// exactly when the equivalent direct path would be. options only contributes
// the file-extension suffix, same as the direct path.
- (BOOL)evaluatePathRestriction:(NSString *)path options:(NSDictionary<NSString *, id> *)options {
    // Add file extension if needed.
    NSString* file_ext = [options objectForKey:kShadowRestrictionFileExtension];

    if(file_ext && ![[path pathExtension] isEqualToString:file_ext]) {
        path = [path stringByAppendingFormat:@".%@", file_ext];
    }

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
    // invalidates immediately. Options are never cached: they alter the
    // decision (working dir, file extension, resolve re-check, symlink
    // resolution).
    BOOL cacheable = ((options == nil) || ([options count] == 0)) && [path isAbsolutePath];

    if(cacheable) {
        NSUInteger gen = [backend rulesetGeneration];
        NSArray* cached = [decisionCache objectForKey:path];

        if(cached) {
            double age = [NSDate timeIntervalSinceReferenceDate] - [[cached objectAtIndex:0] doubleValue];

            if(age >= 0 && age <= kDecisionCacheTTL
                && [[cached objectAtIndex:2] unsignedIntegerValue] == gen) {
                return [[cached objectAtIndex:1] boolValue];
            }
        }
    }

    NSString* original_path = path;
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

    if(shouldCheckPath) {
        NSLog(@"[Shadow] isPathRestricted: allowed path: %@", path);
    }

done:
    if(cacheable) {
        // C0-5: generation tag — a ruleset reload invalidates the entry at
        // the next query even inside the TTL window.
        [decisionCache setObject:@[@([NSDate timeIntervalSinceReferenceDate]), @(restricted), @([backend rulesetGeneration])] forKey:original_path];
    }

    return restricted;
}

- (BOOL)isURLRestricted:(NSURL *)url {
    return [self isURLRestricted:url options:nil];
}

- (BOOL)isURLRestricted:(NSURL *)url options:(NSDictionary<NSString *, id> *)options {
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

- (BOOL)isSchemeRestricted:(NSString *)scheme {
    return [backend isSchemeRestricted:scheme];
}

// C0-3: hidden-app predicate. Static list of well-known package managers and
// jailbreak loaders (case-insensitive; the app-facing surface — LSApplication
// results, openURL, canOpenURL — filters these so a detector can't proxy
// through them), OR any ruleset's BlacklistBundleIDs for user extension.
- (BOOL)isBundleIDRestricted:(NSString *)bundleID {
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

// C0-3: protected-name policy. A single exact-name predicate for the
// dyld/objc/NSBundle/UIImage layers: restricted by ruleset, or one of
// Shadow's own artifacts matched by case-insensitive basename prefix
// (rootful /Library/Frameworks and rootless /var/jb prefixes both reduce to
// the same basename). "substrate"/"substitute"/"ellekit" also match their
// lib-prefixed dylibs (libsubstrate.dylib etc.).
- (BOOL)isProtectedImagePath:(NSString *)path {
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
@end
