#import "hooks.h"

%group shadowhook_NSFileHandle
%hook NSFileHandle
+ (instancetype)fileHandleForReadingAtPath:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForReadingFromURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }
        
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForWritingAtPath:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForWritingToURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }
        
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForUpdatingAtPath:(NSString *)path {
    if(!isCallerTweak() && [_shadow isPathRestricted:path]) {
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForUpdatingURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(!isCallerTweak() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorFileDoesNotExist userInfo:nil];
        }
        
        return nil;
    }
    
    return %orig;
}
%end
%end

void shadowhook_NSFileHandle(HKSubstitutor* hooks) {
    %init(shadowhook_NSFileHandle);
}
