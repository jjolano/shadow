#import "hooks.h"

%group shadowhook_NSBundle
%hook NSBundle
- (id)objectForInfoDictionaryKey:(NSString *)key {
    if(!isCallerTweak() && [key isEqualToString:@"SignerIdentity"]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)bundleWithURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }
    
    return %orig;
}

+ (instancetype)bundleWithPath:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }
    
    return %orig;
}

- (instancetype)initWithURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }
    
    return %orig;
}

- (instancetype)initWithPath:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }
    
    return %orig;
}

+ (NSBundle *)bundleForClass:(Class)aClass {
    if(!isCallerTweak() && [_shadow isAddrRestricted:(void *)aClass]) {
        return nil;
    }

    return %orig;
}

+ (NSBundle *)bundleWithIdentifier:(NSString *)identifier {
    NSBundle* result = %orig;

    if(!isCallerTweak() && result && [_shadow isPathRestricted:[result bundlePath]]) {
        return nil;
    }

    return result;
}

- (NSURL *)URLForResource:(NSString *)name withExtension:(NSString *)ext subdirectory:(NSString *)subpath {
    NSURL* result = %orig;

    if(!isCallerTweak() && [_shadow isURLRestricted:result]) {
        return nil;
    }

    return result;
}

- (NSURL *)URLForResource:(NSString *)name withExtension:(NSString *)ext {
    NSURL* result = %orig;

    if(!isCallerTweak() && [_shadow isURLRestricted:result]) {
        return nil;
    }

    return result;
}

- (NSArray<NSURL *> *)URLsForResourcesWithExtension:(NSString *)ext subdirectory:(NSString *)subpath {
    NSArray* result = %orig;

    if(!isCallerTweak() && result) {
        NSMutableArray* result_filtered = [result mutableCopy];

        for(NSURL* url in result) {
            if([_shadow isURLRestricted:url]) {
                [result_filtered removeObject:url];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (NSURL *)URLForResource:(NSString *)name withExtension:(NSString *)ext subdirectory:(NSString *)subpath localization:(NSString *)localizationName {
    NSURL* result = %orig;

    if(!isCallerTweak() && [_shadow isURLRestricted:result]) {
        return nil;
    }

    return result;
}

- (NSArray<NSURL *> *)URLsForResourcesWithExtension:(NSString *)ext subdirectory:(NSString *)subpath localization:(NSString *)localizationName {
    NSArray* result = %orig;

    if(!isCallerTweak() && result) {
        NSMutableArray* result_filtered = [result mutableCopy];

        for(NSURL* url in result) {
            if([_shadow isURLRestricted:url]) {
                [result_filtered removeObject:url];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

+ (NSURL *)URLForResource:(NSString *)name withExtension:(NSString *)ext subdirectory:(NSString *)subpath inBundleWithURL:(NSURL *)bundleURL {
    NSURL* result = %orig;

    if(!isCallerTweak() && [_shadow isURLRestricted:result]) {
        return nil;
    }

    return result;
}

+ (NSArray<NSURL *> *)URLsForResourcesWithExtension:(NSString *)ext subdirectory:(NSString *)subpath inBundleWithURL:(NSURL *)bundleURL {
    NSArray* result = %orig;

    if(!isCallerTweak() && result) {
        NSMutableArray* result_filtered = [result mutableCopy];

        for(NSURL* url in result) {
            if([_shadow isURLRestricted:url]) {
                [result_filtered removeObject:url];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (NSString *)pathForResource:(NSString *)name ofType:(NSString *)ext {
    NSString* result = %orig;

    if(!isCallerTweak() && [_shadow isPathRestricted:result]) {
        return nil;
    }

    return result;
}

- (NSString *)pathForResource:(NSString *)name ofType:(NSString *)ext inDirectory:(NSString *)subpath {
    NSString* result = %orig;

    if(!isCallerTweak() && [_shadow isPathRestricted:result]) {
        return nil;
    }

    return result;
}

- (NSString *)pathForResource:(NSString *)name ofType:(NSString *)ext inDirectory:(NSString *)subpath forLocalization:(NSString *)localizationName {
    NSString* result = %orig;

    if(!isCallerTweak() && [_shadow isPathRestricted:result]) {
        return nil;
    }

    return result;
}

- (NSArray<NSString *> *)pathsForResourcesOfType:(NSString *)ext inDirectory:(NSString *)subpath {
    NSArray* result = %orig;

    if(!isCallerTweak() && result) {
        NSMutableArray* result_filtered = [result mutableCopy];

        for(NSString* path in result) {
            if([_shadow isPathRestricted:path]) {
                [result_filtered removeObject:path];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (NSArray<NSString *> *)pathsForResourcesOfType:(NSString *)ext inDirectory:(NSString *)subpath forLocalization:(NSString *)localizationName {
    NSArray* result = %orig;

    if(!isCallerTweak() && result) {
        NSMutableArray* result_filtered = [result mutableCopy];

        for(NSString* path in result) {
            if([_shadow isPathRestricted:path]) {
                [result_filtered removeObject:path];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

+ (NSString *)pathForResource:(NSString *)name ofType:(NSString *)ext inDirectory:(NSString *)bundlePath {
    NSString* result = %orig;

    if(!isCallerTweak() && [_shadow isPathRestricted:result]) {
        return nil;
    }

    return result;
}

+ (NSArray<NSString *> *)pathsForResourcesOfType:(NSString *)ext inDirectory:(NSString *)bundlePath {
    NSArray* result = %orig;

    if(!isCallerTweak() && result) {
        NSMutableArray* result_filtered = [result mutableCopy];

        for(NSString* path in result) {
            if([_shadow isPathRestricted:path]) {
                [result_filtered removeObject:path];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

+ (NSArray<NSBundle *> *)allBundles {
    NSArray* result = %orig;

    if(!isCallerTweak() && result) {
        NSMutableArray* result_filtered = [result mutableCopy];

        for(NSBundle* bundle in result) {
            if([_shadow isPathRestricted:[bundle bundlePath]]) {
                [result_filtered removeObject:bundle];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

+ (NSArray<NSBundle *> *)allFrameworks {
    NSArray* result = %orig;

    if(!isCallerTweak() && result) {
        NSMutableArray* result_filtered = [result mutableCopy];

        for(NSBundle* bundle in result) {
            if([_shadow isPathRestricted:[bundle bundlePath]]) {
                [result_filtered removeObject:bundle];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}
%end
%end

void shadowhook_NSBundle(HKSubstitutor* hooks) {
    %init(shadowhook_NSBundle);
}
