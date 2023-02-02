#import "hooks.h"

%group shadowhook_NSData
%hook NSData
+ (instancetype)dataWithContentsOfFile:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        if(errorPtr) {
            *errorPtr = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(errorPtr) {
            *errorPtr = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        if(errorPtr) {
            *errorPtr = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(errorPtr) {
            *errorPtr = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfMappedFile:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (id)dataWithContentsOfMappedFile:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_NSData(HKSubstitutor* hooks) {
    %init(shadowhook_NSData);
}
