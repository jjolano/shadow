#import "hooks.h"

%group shadowhook_NSArray
%hook NSArray
- (id)initWithContentsOfFile:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfFile:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

- (NSArray *)initWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (NSArray *)arrayWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}
%end

%hook NSMutableArray
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

+ (id)arrayWithContentsOfFile:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_NSArray(HKSubstitutor* hooks) {
    %init(shadowhook_NSArray);
}
