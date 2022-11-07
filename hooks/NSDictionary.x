#import "hooks.h"

%group shadowhook_NSDictionary
%hook NSDictionary
- (id)initWithContentsOfFile:(NSString *)path {
    NSDictionary* result = %orig;

    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    NSDictionary* result = %orig;

    if(result && [_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

- (id)initWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    NSDictionary* result = %orig;

    if(result && [_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

+ (id)dictionaryWithContentsOfFile:(NSString *)path {
    NSDictionary* result = %orig;

    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    NSDictionary* result = %orig;

    if(result && [_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url {
    NSDictionary* result = %orig;

    if(result && [_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}
%end

%hook NSMutableDictionary
- (id)initWithContentsOfFile:(NSString *)path {
    NSMutableDictionary* result = %orig;

    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    NSMutableDictionary* result = %orig;

    if(result && [_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

+ (NSMutableDictionary *)dictionaryWithContentsOfFile:(NSString *)path {
    NSMutableDictionary* result = %orig;

    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

+ (NSMutableDictionary *)dictionaryWithContentsOfURL:(NSURL *)url {
    NSMutableDictionary* result = %orig;

    if(result && [_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}
%end
%end

void shadowhook_NSDictionary(void) {
    %init(shadowhook_NSDictionary);
}
