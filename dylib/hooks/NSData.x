#import "hooks.h"

%group shadowhook_NSData
%hook NSData
+ (instancetype)dataWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(errorPtr) {
            *errorPtr = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(errorPtr) {
            *errorPtr = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(errorPtr) {
            *errorPtr = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    if([_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(errorPtr) {
            *errorPtr = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfMappedFile:(NSString *)path {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}

+ (id)dataWithContentsOfMappedFile:(NSString *)path {
    if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_NSData(HKSubstitutor* hooks) {
    %init(shadowhook_NSData);
}
