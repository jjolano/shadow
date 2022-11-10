#import "hooks.h"

%group shadowhook_NSBundle
%hook NSBundle
- (id)objectForInfoDictionaryKey:(NSString *)key {
    if([key isEqualToString:@"SignerIdentity"] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)bundleWithURL:(NSURL *)url {
    NSBundle* result = %orig;

    HBLogDebug(@"%@: %@: %@: %@", @"NSBundle", @"bundleWithURL", url, result);

    if(result && [_shadow isURLRestricted:[result bundleURL]] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }
    
    return result;
}

+ (instancetype)bundleWithPath:(NSString *)path {
    NSBundle* result = %orig;

    HBLogDebug(@"%@: %@: %@: %@", @"NSBundle", @"bundleWithPath", path, result);

    if(result && [_shadow isPathRestricted:[result bundlePath]] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }
    
    return result;
}

- (instancetype)initWithURL:(NSURL *)url {
    NSBundle* result = %orig;

    HBLogDebug(@"%@: %@: %@: %@", @"NSBundle", @"initWithURL", url, result);

    if(result && [_shadow isURLRestricted:[result bundleURL]] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }
    
    return result;
}

- (instancetype)initWithPath:(NSString *)path {
    NSBundle* result = %orig;

    HBLogDebug(@"%@: %@: %@: %@", @"NSBundle", @"initWithPath", path, result);

    if(result && [_shadow isPathRestricted:[result bundlePath]] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }
    
    return result;
}

+ (NSBundle *)bundleForClass:(Class)aClass {
    NSBundle* result = %orig;

    HBLogDebug(@"%@: %@: %@", @"NSBundle", @"bundleForClass", aClass);

    if(result && [_shadow isPathRestricted:[result bundlePath]] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

+ (NSBundle *)bundleWithIdentifier:(NSString *)identifier {
    NSBundle* result = %orig;

    HBLogDebug(@"%@: %@: %@", @"NSBundle", @"bundleWithIdentifier", identifier);

    if(result && [_shadow isPathRestricted:[result bundlePath]] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

- (NSURL *)URLForResource:(NSString *)name withExtension:(NSString *)ext subdirectory:(NSString *)subpath {
    NSURL* result = %orig;

    if(result && [_shadow isURLRestricted:result] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

- (NSURL *)URLForResource:(NSString *)name withExtension:(NSString *)ext {
    NSURL* result = %orig;

    if(result && [_shadow isURLRestricted:result] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

- (NSArray<NSURL *> *)URLsForResourcesWithExtension:(NSString *)ext subdirectory:(NSString *)subpath {
    NSArray* result = %orig;

    if(result && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        NSMutableArray* result_filtered = [NSMutableArray new];

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

    if(result && [_shadow isURLRestricted:result] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

- (NSArray<NSURL *> *)URLsForResourcesWithExtension:(NSString *)ext subdirectory:(NSString *)subpath localization:(NSString *)localizationName {
    NSArray* result = %orig;

    if(result && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        NSMutableArray* result_filtered = [NSMutableArray new];

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

    if(result && [_shadow isURLRestricted:result] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

+ (NSArray<NSURL *> *)URLsForResourcesWithExtension:(NSString *)ext subdirectory:(NSString *)subpath inBundleWithURL:(NSURL *)bundleURL {
    NSArray* result = %orig;

    if(result && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        NSMutableArray* result_filtered = [NSMutableArray new];

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

    if(result && [_shadow isPathRestricted:result] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

- (NSString *)pathForResource:(NSString *)name ofType:(NSString *)ext inDirectory:(NSString *)subpath {
    NSString* result = %orig;

    if(result && [_shadow isPathRestricted:result] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

- (NSString *)pathForResource:(NSString *)name ofType:(NSString *)ext inDirectory:(NSString *)subpath forLocalization:(NSString *)localizationName {
    NSString* result = %orig;

    if(result && [_shadow isPathRestricted:result] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

- (NSArray<NSString *> *)pathsForResourcesOfType:(NSString *)ext inDirectory:(NSString *)subpath {
    NSArray* result = %orig;

    if(result && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        NSMutableArray* result_filtered = [NSMutableArray new];

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

    if(result && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        NSMutableArray* result_filtered = [NSMutableArray new];

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

    if(result && [_shadow isPathRestricted:result] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

+ (NSArray<NSString *> *)pathsForResourcesOfType:(NSString *)ext inDirectory:(NSString *)bundlePath {
    NSArray* result = %orig;

    if(result && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        NSMutableArray* result_filtered = [NSMutableArray new];

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

    if(result && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        NSMutableArray* result_filtered = [NSMutableArray new];

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

    if(result && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        NSMutableArray* result_filtered = [NSMutableArray new];

        for(NSBundle* bundle in result) {
            if(![_shadow isPathRestricted:[bundle bundlePath]]) {
                [result_filtered addObject:bundle];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}
%end
%end

void shadowhook_NSBundle(void) {
    %init(shadowhook_NSBundle);
}
