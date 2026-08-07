#import "hooks.h"

// Write/create intent for handle-open mutations: a probe opening a handle
// for writing at a restricted-classified path must be denied even when the
// target does not exist yet.
static NSDictionary* _shdw_handleWriteOptions(void) {
    return @{kShadowRestrictionOperation : kShadowRestrictionOpWrite};
}

%group shadowhook_NSFileHandle
%hook NSFileHandle
// TODO(plan-wave-C): fd-based surfaces (initWithFileDescriptor:,
// fileDescriptor, read/write methods) are out of scope — they need an
// F_GETPATH fd→path resolver; pipes/sockets must pass through untouched.
+ (instancetype)fileHandleForReadingAtPath:(NSString *)path {
    if(!isCallerExternal() && [_shadow isPathRestricted:path]) {
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForReadingFromURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(!isCallerExternal() && [_shadow isURLRestricted:url]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }
        
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForWritingAtPath:(NSString *)path {
    if(!isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_handleWriteOptions()]) {
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForWritingToURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(!isCallerExternal() && [_shadow isURLRestricted:url options:_shdw_handleWriteOptions()]) {
        if(error) {
            *error = [Shadow fileNoSuchFileErrorForURL:url];
        }
        
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForUpdatingAtPath:(NSString *)path {
    if(!isCallerExternal() && [_shadow isPathRestricted:path options:_shdw_handleWriteOptions()]) {
        return nil;
    }
    
    return %orig;
}

+ (instancetype)fileHandleForUpdatingURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if(!isCallerExternal() && [_shadow isURLRestricted:url options:_shdw_handleWriteOptions()]) {
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
