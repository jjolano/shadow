#import <Shadow/Core.h>
#import <Shadow/Core+Utilities.h>
#import <Shadow/Backend.h>
#import <Shadow/JBPath.h>

#import <dlfcn.h>
#import <pwd.h>
#import <stdlib.h>

#import "../vendor/apple/dyld_priv.h"
#import "../common.h"

// C0-2: Shadow-internal read scope flag. Shadow-owned code wraps its own
// filesystem reads in SHADOW_INTERNAL_SCOPE (see Core.h) so the tweak's own
// hooks never filter them. A depth counter (not a BOOL) so nested scopes —
// e.g. the ruleset store's change check → reload → load — stay busy until
// the outermost scope exits. _Thread_local because scopes are strictly
// same-thread (the hook that reads the flag runs on the thread that entered
// the scope).
//
// EXPORTED as a plain C thread-local, not only through the class methods
// below. isCallerExternal() reads this on every one of ~400 hook entry
// points; reaching it by objc_msgSend across the framework boundary meant a
// cross-image message send on the hottest path in the tweak. Reading the
// thread-local directly is strictly less work and lets isCallerExternal stay
// a pure inline. (Darwin exports thread-locals like any other symbol — the
// TLV descriptor goes in the export list — so the earlier "a C TLS symbol
// cannot cross the export list" note was simply wrong.)
//
// Measured effect on launch CPU: below the noise floor on the app tested
// (Bitwarden), whose launch cost is dominated by the per-path engine
// pipeline, not hook-entry overhead. Kept because it is correct and cheaper,
// not because it moved that number.
__attribute__((visibility("default")))
_Thread_local NSUInteger shdw_internal_busy = 0;

@implementation Shadow
@synthesize bundlePath, homePath, realHomePath, hasAppSandbox, rootless;

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

    // No indicator fast-path here (the lane's strstr list was reverted): a
    // ruleset can deny ANY path (test rulesets, user blacklists), so a C
    // surface that short-circuits indicator-free paths would diverge from
    // the ObjC surface — the differential contract (tests/main.m) requires
    // them to agree. The rootful /Library prefixes and the canonical
    // indicator strings are denied by the shipped rulesets via the full
    // pipeline below; the indicator prefilters that remain live in
    // ShadowCore (shdw_path_can_be_restricted), where the sites judge only
    // image paths or are mandated by the *at contract.

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

// Candidate 5: legacy dictionary -> typed query translation. Only the four
// published keys are read; unknown keys were never read by the pipeline (they
// only disabled the decision cache via [options count] > 0, which the typed
// pipeline preserves by caching only default-shaped queries).
static ShadowRestrictionQuery* shdwQueryFromOptions(NSString* path, NSDictionary<NSString*, id>* options) {
    ShadowRestrictionQuery* query = [ShadowRestrictionQuery queryWithPath:path];
    query.flags = ShadowRestrictionFlagResolve;
    query.operation = ShadowRestrictionOperationRead;

    if(!options) {
        return query;
    }

    id resolve = [options objectForKey:kShadowRestrictionEnableResolve];

    if(resolve && ![resolve boolValue]) {
        query.flags &= ~ShadowRestrictionFlagResolve;
    }

    if([[options objectForKey:kShadowRestrictionNoFollow] boolValue]) {
        query.flags |= ShadowRestrictionFlagNoFollow;
    }

    if([[options objectForKey:kShadowRestrictionOperation] isEqualToString:kShadowRestrictionOpWrite]) {
        query.operation = ShadowRestrictionOperationWrite;
    }

    NSString* wd = [options objectForKey:kShadowRestrictionWorkingDir];

    if(wd) {
        query.workingDirectory = wd;
    }

    return query;
}

// Candidate 5: the dictionary methods translate to the typed entry point.
- (BOOL)isPathRestricted:(NSString *)path options:(NSDictionary<NSString *, id> *)options {
    return [self isPathRestrictedQuery:shdwQueryFromOptions(path, options)];
}

// Candidate 5: typed entry point — the facade delegates to the engine
// (RestrictionEngine.m), which evaluates with the resolver-based engine.
- (BOOL)isPathRestrictedQuery:(ShadowRestrictionQuery *)query {
    // C0-2 recursion guard: the engine's own path normalization
    // (getStandardizedPath:) constructs NSURLs via +[NSURL fileURLWithPath:],
    // whose Foundation init internally calls the hooked
    // fileExistsAtPath:isDirectory: — with the caller's return address inside
    // Foundation, isCallerExternal() classifies it EXTERNAL and re-enters the
    // engine: unbounded recursion (observed on-device: Bitwarden SIGSEGV at
    // launch, 500+ frames of engine <-> fileURLWithPath). The internal-read
    // scope makes every nested hook call classify as Shadow-internal and
    // short-circuit to its original while the engine evaluates; the verdict
    // the outer (real) caller sees is unchanged.
    BOOL restricted = NO;

    SHADOW_INTERNAL_SCOPE {
        restricted = [backend isPathRestrictedQuery:query];
    }

    return restricted;
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

@implementation ShadowRestrictionQuery

+ (instancetype)queryWithPath:(NSString *)path {
    ShadowRestrictionQuery* query = [self new];
    query.path = path;
    query.operation = ShadowRestrictionOperationRead;
    query.flags = ShadowRestrictionFlagResolve;
    return query;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"<ShadowRestrictionQuery path=%@ wd=%@ op=%ld flags=%lu>",
        self.path, self.workingDirectory, (long)self.operation, (unsigned long)self.flags];
}
@end
