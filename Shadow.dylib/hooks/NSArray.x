#import "hooks.h"

%group shadowhook_NSArray
%hook NSArray
- (id)initWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfURL:(NSURL *)url {
    if([_shadow isURLRestricted:url] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}

- (NSArray *)initWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url] && !isCallerTweak()) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (NSArray *)arrayWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url] && !isCallerTweak()) {
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
    if([_shadow isPathRestricted:path] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    if([_shadow isURLRestricted:url] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfURL:(NSURL *)url {
    if([_shadow isURLRestricted:url] && !isCallerTweak()) {
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_NSArray(HKSubstitutor* hooks) {
    %init(shadowhook_NSArray);
}
