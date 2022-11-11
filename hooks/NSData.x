#import "hooks.h"

%group shadowhook_NSData
%hook NSData
+ (instancetype)dataWithContentsOfFile:(NSString *)path {
    NSData* result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

+ (instancetype)dataWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    NSData* result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(errorPtr) {
            *errorPtr = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return result;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url {
    NSData* result = %orig;
    
    if(result && [_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    NSData* result = %orig;
    
    if(result && [_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(errorPtr) {
            *errorPtr = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return result;
}

- (instancetype)initWithContentsOfFile:(NSString *)path {
    NSData* result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

- (instancetype)initWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    NSData* result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(errorPtr) {
            *errorPtr = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }

        return nil;
    }

    return result;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url {
    NSData* result = %orig;
    
    if(result && [_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
    NSData* result = %orig;
    
    if(result && [_shadow isURLRestricted:url] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        if(errorPtr) {
            *errorPtr = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }

        return nil;
    }

    return result;
}

- (id)initWithContentsOfMappedFile:(NSString *)path {
    NSData* result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}

+ (id)dataWithContentsOfMappedFile:(NSString *)path {
    NSData* result = %orig;
    
    if(result && [_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return nil;
    }

    return result;
}
%end
%end

void shadowhook_NSData(void) {
    %init(shadowhook_NSData);
}
