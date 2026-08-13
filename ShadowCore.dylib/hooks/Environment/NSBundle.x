#import "hooks.h"

// Main-bundle path/URL captured once at install (CF API: bypasses the
// Objective-C dispatch entirely, so a protected-bundle branch can never
// re-enter the bundlePath/bundleURL hooks it sits inside). The value is
// immutable for the process lifetime, so the statics need no locking.
static NSString* _shdw_main_bundle_path;
static NSURL* _shdw_main_bundle_url;

static void shdw_cache_main_bundle(void) {
    CFURLRef url = CFBundleCopyBundleURL(CFBundleGetMainBundle());

    if(url) {
        _shdw_main_bundle_url = CFBridgingRelease(url);
        _shdw_main_bundle_path = [_shdw_main_bundle_url path];
    }

    // ponytail: CFBundleCopyBundleURL never fails for a running main bundle;
    // if it somehow did, both statics stay nil and the hooks fall back to
    // their original result (internal-caller classification still guards
    // Shadow's own reads).
}

%group shadowhook_NSBundle
%hook NSBundle
- (id)objectForInfoDictionaryKey:(NSString *)key {
    if(isCallerExternal() && [key isEqualToString:@"SignerIdentity"]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)bundleWithURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);
    
    return %orig;
}

+ (instancetype)bundleWithPath:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);
    
    return %orig;
}

- (instancetype)initWithURL:(NSURL *)url {
    SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url);
    
    return %orig;
}

- (instancetype)initWithPath:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);
    
    return %orig;
}

+ (NSBundle *)bundleForClass:(Class)aClass {
    if(isCallerExternal() && shdw_addr_is_restricted((__bridge const void *)aClass)) {
        // Nonnull contract: report the main bundle, never nil.
        return [NSBundle mainBundle];
    }

    return %orig;
}

+ (NSBundle *)bundleWithIdentifier:(NSString *)identifier {
    NSBundle* result = %orig;

    if(isCallerExternal() && result && [_shadow isPathRestricted:[result bundlePath]]) {
        return nil;
    }

    return result;
}

- (NSURL *)URLForResource:(NSString *)name withExtension:(NSString *)ext subdirectory:(NSString *)subpath {
    NSURL* result = %orig;

    if(isCallerExternal() && [_shadow isURLRestricted:result]) {
        return nil;
    }

    return result;
}

- (NSURL *)URLForResource:(NSString *)name withExtension:(NSString *)ext {
    NSURL* result = %orig;

    if(isCallerExternal() && [_shadow isURLRestricted:result]) {
        return nil;
    }

    return result;
}

- (NSArray<NSURL *> *)URLsForResourcesWithExtension:(NSString *)ext subdirectory:(NSString *)subpath {
    NSArray* result = %orig;

    if(isCallerExternal() && result) {
        NSMutableArray* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSURL* url in result) {
            if(![_shadow isURLRestricted:url]) {
                [result_filtered addObject:url];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (NSURL *)URLForResource:(NSString *)name withExtension:(NSString *)ext subdirectory:(NSString *)subpath localization:(NSString *)localizationName {
    NSURL* result = %orig;

    if(isCallerExternal() && [_shadow isURLRestricted:result]) {
        return nil;
    }

    return result;
}

- (NSArray<NSURL *> *)URLsForResourcesWithExtension:(NSString *)ext subdirectory:(NSString *)subpath localization:(NSString *)localizationName {
    NSArray* result = %orig;

    if(isCallerExternal() && result) {
        NSMutableArray* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSURL* url in result) {
            if(![_shadow isURLRestricted:url]) {
                [result_filtered addObject:url];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

+ (NSURL *)URLForResource:(NSString *)name withExtension:(NSString *)ext subdirectory:(NSString *)subpath inBundleWithURL:(NSURL *)bundleURL {
    NSURL* result = %orig;

    if(isCallerExternal() && [_shadow isURLRestricted:result]) {
        return nil;
    }

    return result;
}

+ (NSArray<NSURL *> *)URLsForResourcesWithExtension:(NSString *)ext subdirectory:(NSString *)subpath inBundleWithURL:(NSURL *)bundleURL {
    NSArray* result = %orig;

    if(isCallerExternal() && result) {
        NSMutableArray* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSURL* url in result) {
            if(![_shadow isURLRestricted:url]) {
                [result_filtered addObject:url];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (NSString *)pathForResource:(NSString *)name ofType:(NSString *)ext {
    NSString* result = %orig;

    if(isCallerExternal() && [_shadow isPathRestricted:result]) {
        return nil;
    }

    return result;
}

- (NSString *)pathForResource:(NSString *)name ofType:(NSString *)ext inDirectory:(NSString *)subpath {
    NSString* result = %orig;

    if(isCallerExternal() && [_shadow isPathRestricted:result]) {
        return nil;
    }

    return result;
}

- (NSString *)pathForResource:(NSString *)name ofType:(NSString *)ext inDirectory:(NSString *)subpath forLocalization:(NSString *)localizationName {
    NSString* result = %orig;

    if(isCallerExternal() && [_shadow isPathRestricted:result]) {
        return nil;
    }

    return result;
}

- (NSArray<NSString *> *)pathsForResourcesOfType:(NSString *)ext inDirectory:(NSString *)subpath {
    NSArray* result = %orig;

    if(isCallerExternal() && result) {
        NSMutableArray* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSString* path in result) {
            if(![_shadow isPathRestricted:path]) {
                [result_filtered addObject:path];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (NSArray<NSString *> *)pathsForResourcesOfType:(NSString *)ext inDirectory:(NSString *)subpath forLocalization:(NSString *)localizationName {
    NSArray* result = %orig;

    if(isCallerExternal() && result) {
        NSMutableArray* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSString* path in result) {
            if(![_shadow isPathRestricted:path]) {
                [result_filtered addObject:path];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

+ (NSString *)pathForResource:(NSString *)name ofType:(NSString *)ext inDirectory:(NSString *)bundlePath {
    NSString* result = %orig;

    if(isCallerExternal() && [_shadow isPathRestricted:result]) {
        return nil;
    }

    return result;
}

+ (NSArray<NSString *> *)pathsForResourcesOfType:(NSString *)ext inDirectory:(NSString *)bundlePath {
    NSArray* result = %orig;

    if(isCallerExternal() && result) {
        NSMutableArray* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSString* path in result) {
            if(![_shadow isPathRestricted:path]) {
                [result_filtered addObject:path];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

+ (NSArray<NSBundle *> *)allBundles {
    NSArray* result = %orig;

    if(isCallerExternal() && result) {
        NSMutableArray* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSBundle* bundle in result) {
            if(![_shadow isPathRestricted:[bundle bundlePath]]) {
                [result_filtered addObject:bundle];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

+ (NSArray<NSBundle *> *)allFrameworks {
    NSArray* result = %orig;

    if(isCallerExternal() && result) {
        NSMutableArray* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSBundle* bundle in result) {
            if(![_shadow isPathRestricted:[bundle bundlePath]]) {
                [result_filtered addObject:bundle];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

// ponytail: restricted receivers are unreachable in practice — every bundle
// creation path nils or filters them (bundleWithPath/URL, initWithPath/URL,
// bundleWithIdentifier, allBundles/allFrameworks), and +bundleForClass:
// redirects protected classes to the main bundle. These checks are
// defense-in-depth for objects created before the hooks installed.

- (NSDictionary<NSString *, id> *)infoDictionary {
    NSDictionary* result = %orig;

    if(isCallerExternal() && result && [_shadow isProtectedImagePath:[self bundlePath]]) {
        NSMutableDictionary* filtered_result = [result mutableCopy];
        [filtered_result removeObjectForKey:@"SignerIdentity"];
        result = [filtered_result copy];
    }

    return result;
}

- (NSDictionary<NSString *, id> *)localizedInfoDictionary {
    NSDictionary* result = %orig;

    if(isCallerExternal() && result && [_shadow isProtectedImagePath:[self bundlePath]]) {
        NSMutableDictionary* filtered_result = [result mutableCopy];
        [filtered_result removeObjectForKey:@"SignerIdentity"];
        result = [filtered_result copy];
    }

    return result;
}

// Path getters check the ORIGINAL result (no receiver-path circularity): a
// protected path is replaced with the main-bundle equivalent for the
// nonnull contracts (bundlePath/bundleURL) and nilled for the rest.
- (NSString *)bundlePath {
    NSString* result = %orig;

    if(isCallerExternal() && [_shadow isProtectedImagePath:result]) {
        return _shdw_main_bundle_path ?: result;
    }

    return result;
}

- (NSURL *)bundleURL {
    NSURL* result = %orig;

    if(isCallerExternal() && [_shadow isProtectedImagePath:[result path]]) {
        return _shdw_main_bundle_url ?: result;
    }

    return result;
}

- (NSString *)resourcePath {
    NSString* result = %orig;

    if(isCallerExternal() && [_shadow isProtectedImagePath:result]) {
        return nil;
    }

    return result;
}

- (NSURL *)resourceURL {
    NSURL* result = %orig;

    if(isCallerExternal() && [_shadow isProtectedImagePath:[result path]]) {
        return nil;
    }

    return result;
}

- (NSString *)executablePath {
    NSString* result = %orig;

    if(isCallerExternal() && [_shadow isProtectedImagePath:result]) {
        return nil;
    }

    return result;
}

- (NSURL *)executableURL {
    NSURL* result = %orig;

    if(isCallerExternal() && [_shadow isProtectedImagePath:[result path]]) {
        return nil;
    }

    return result;
}

- (NSString *)pathForAuxiliaryExecutable:(NSString *)executableName {
    NSString* result = %orig;

    if(isCallerExternal() && [_shadow isPathRestricted:result]) {
        return nil;
    }

    return result;
}

- (NSURL *)URLForAuxiliaryExecutable:(NSString *)executableName {
    NSURL* result = %orig;

    if(isCallerExternal() && [_shadow isURLRestricted:result]) {
        return nil;
    }

    return result;
}

- (BOOL)isLoaded {
    if(isCallerExternal() && [_shadow isProtectedImagePath:[self bundlePath]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)load {
    if(isCallerExternal() && [_shadow isProtectedImagePath:[self bundlePath]]) {
        return NO;
    }

    return %orig;
}

- (BOOL)loadAndReturnError:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isProtectedImagePath:[self bundlePath]]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:[self bundlePath]];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)preflightAndReturnError:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isProtectedImagePath:[self bundlePath]]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForPath:[self bundlePath]];
        }

        return NO;
    }

    return %orig;
}

- (BOOL)unload {
    if(isCallerExternal() && [_shadow isProtectedImagePath:[self bundlePath]]) {
        // No-op for restricted receivers.
        return NO;
    }

    return %orig;
}
%end
%end

void shadowhook_NSBundle(HKSubstitutor* hooks) {
    shdw_cache_main_bundle();
    %init(shadowhook_NSBundle);
}
