#import "hooks.h"

%group shadowhook_NSFileHandle
%hook NSFileHandle
// fd-based surfaces: resolve the fd to a path via F_GETPATH. The call
// fails (EBADF, ENOTSUP) for pipes/sockets/other non-files — those pass
// through untouched. `options` is the restriction op for the surface:
// shdw_restriction_write_options() for write surfaces, nil for reads.
static BOOL shdw_fd_is_restricted(int fd, NSDictionary* options) {
    char pathname[PATH_MAX];

    if(fcntl(fd, F_GETPATH, pathname) == -1) {
        return NO;
    }

    return [_shadow isPathRestricted:@(pathname) options:options];
}

- (instancetype)initWithFileDescriptor:(int)fd closeOnDealloc:(BOOL)closeOpt {
    if(isCallerExternal() && shdw_fd_is_restricted(fd, shdw_restriction_write_options())) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithFileDescriptor:(int)fd {
    if(isCallerExternal() && shdw_fd_is_restricted(fd, shdw_restriction_write_options())) {
        return nil;
    }

    return %orig;
}

- (int)fileDescriptor {
    // %orig is a pure getter; safe to evaluate in the gate and pass through.
    int fd = %orig;

    if(isCallerExternal() && shdw_fd_is_restricted(fd, shdw_restriction_write_options())) {
        return -1;
    }

    return fd;
}

- (NSData *)readDataToEndOfFile {
    // [self fileDescriptor] resolves the real fd: the fileDescriptor hook
    // passes Shadow's own caller (this hook body) through untouched.
    if(isCallerExternal() && shdw_fd_is_restricted([self fileDescriptor], nil)) {
        return [NSData data];
    }

    return %orig;
}

- (NSData *)readDataOfLength:(NSUInteger)length {
    if(isCallerExternal() && shdw_fd_is_restricted([self fileDescriptor], nil)) {
        return [NSData data];
    }

    return %orig;
}

- (NSData *)availableData {
    if(isCallerExternal() && shdw_fd_is_restricted([self fileDescriptor], nil)) {
        return [NSData data];
    }

    return %orig;
}

- (void)writeData:(NSData *)data {
    if(isCallerExternal() && shdw_fd_is_restricted([self fileDescriptor], shdw_restriction_write_options())) {
        return;
    }

    return %orig;
}

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
