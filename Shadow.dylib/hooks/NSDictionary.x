#import "hooks.h"

%group shadowhook_NSDictionary
%hook NSDictionary
- (id)initWithContentsOfFile:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }
        
        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfFile:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}
%end

%hook NSMutableDictionary
- (id)initWithContentsOfFile:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (NSMutableDictionary *)dictionaryWithContentsOfFile:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (NSMutableDictionary *)dictionaryWithContentsOfURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_NSDictionary(HKSubstitutor* hooks) {
    %init(shadowhook_NSDictionary);
}
