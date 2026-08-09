#import "hooks.h"

%group shadowhook_NSFileHandle
%hook NSFileHandle
// TODO(plan-wave-C): fd-based surfaces (initWithFileDescriptor:,
// fileDescriptor, read/write methods) are out of scope — they need an
// F_GETPATH fd→path resolver; pipes/sockets must pass through untouched.
+ (instancetype)fileHandleForReadingAtPath:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);
    
    return %orig;
}

+ (instancetype)fileHandleForReadingFromURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }
        
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForWritingAtPath:(NSString *)path {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:shdw_restriction_write_options()]) {
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForWritingToURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:shdw_restriction_write_options()]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }
        
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForUpdatingAtPath:(NSString *)path {
    if(isCallerExternal() && [_shadow isPathRestricted:path options:shdw_restriction_write_options()]) {
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForUpdatingURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(isCallerExternal() && [_shadow isURLRestricted:url options:shdw_restriction_write_options()]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
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
