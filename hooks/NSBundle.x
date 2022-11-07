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

    if(result && [_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }
    
    return result;
}

+ (instancetype)bundleWithPath:(NSString *)path {
    NSBundle* result = %orig;

    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }
    
    return result;
}

- (instancetype)initWithURL:(NSURL *)url {
    NSBundle* result = %orig;

    if(result && [_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }
    
    return result;
}

- (instancetype)initWithPath:(NSString *)path {
    NSBundle* result = %orig;

    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }
    
    return result;
}
%end
%end

void shadowhook_NSBundle(void) {
    %init(shadowhook_NSBundle);
}
