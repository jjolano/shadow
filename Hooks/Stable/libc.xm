#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <spawn.h>
#include <fcntl.h>

%group hook_libc
%hookf(int, access, const char *pathname, int mode) {
    if(!pathname) {
        return %orig;
    }

    NSString *path = [NSString stringWithUTF8String:pathname];

    // workaround for tweaks not loading properly in Substrate
    if([_shadow useSubstrateCompatibilityMode] && [[path pathExtension] isEqualToString:@"plist"] && [path containsString:@"DynamicLibraries/"]) {
        return %orig;
    }

    if([_shadow isPathRestricted:path]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}

%hookf(char *, getenv, const char *name) {
    if(!name) {
        return %orig;
    }

    NSString *env = [NSString stringWithUTF8String:name];

    if([env isEqualToString:@"DYLD_INSERT_LIBRARIES"]
    || [env isEqualToString:@"_MSSafeMode"]
    || [env isEqualToString:@"_SafeMode"]) {
        return NULL;
    }

    return %orig;
}

%hookf(FILE *, fopen, const char *pathname, const char *mode) {
    if(!pathname) {
        return %orig;
    }
    
    if([_shadow isPathRestricted:[NSString stringWithUTF8String:pathname]]) {
        errno = ENOENT;
        return NULL;
    }

    return %orig;
}

%hookf(int, stat, const char *pathname, struct stat *statbuf) {
    if(!pathname) {
        return %orig;
    }

    if([_shadow isPathRestricted:[NSString stringWithUTF8String:pathname]]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}

%hookf(int, lstat, const char *pathname, struct stat *statbuf) {
    if(!pathname) {
        return %orig;
    }

    if([_shadow isPathRestricted:[NSString stringWithUTF8String:pathname]]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}

%hookf(int, statfs, const char *path, struct statfs *buf) {
    if(!path) {
        return %orig;
    }

    int ret = %orig;

    if(ret == 0) {
        NSString *pathname = [NSString stringWithUTF8String:path];

        pathname = [_shadow resolveLinkInPath:pathname];
        
        if(![pathname hasPrefix:@"/var"]
        && ![pathname hasPrefix:@"/private/var"]) {
            if(buf) {
                // Ensure root is marked read-only.
                buf->f_flags |= MNT_RDONLY;
                return ret;
            }
        }

        if([_shadow isPathRestricted:pathname]) {
            errno = ENOENT;
            return -1;
        }
    }

    return ret;
}

%hookf(int, posix_spawn, pid_t *pid, const char *pathname, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    if(!pathname) {
        return %orig;
    }

    NSString *path = [NSString stringWithUTF8String:pathname];

    if([_shadow isPathRestricted:path]) {
        return ENOSYS;
    }

    return %orig;
}

%hookf(int, posix_spawnp, pid_t *pid, const char *pathname, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    if(!pathname) {
        return %orig;
    }

    NSString *path = [NSString stringWithUTF8String:pathname];

    if([_shadow isPathRestricted:path]) {
        return ENOSYS;
    }

    return %orig;
}

%hookf(char *, realpath, const char *pathname, char *resolved_path) {
    if(!pathname) {
        return %orig;
    }

    if([_shadow isPathRestricted:[NSString stringWithUTF8String:pathname]]) {
        errno = ENOENT;
        return NULL;
    }

    return %orig;
}

%hookf(int, symlink, const char *path1, const char *path2) {
    if(!path1 || !path2) {
        return %orig;
    }

    if([_shadow isPathRestricted:[NSString stringWithUTF8String:path2]]) {
        errno = ENOENT;
        return -1;
    }

    int ret = %orig;

    if(ret == 0) {
        // Track this symlink in Shadow
        [_shadow addPath:[NSString stringWithUTF8String:path1] toPath:[NSString stringWithUTF8String:path2]];
    }

    return ret;
}

%hookf(int, link, const char *path1, const char *path2) {
    if(!path1 || !path2) {
        return %orig;
    }

    if([_shadow isPathRestricted:[NSString stringWithUTF8String:path2]]) {
        errno = ENOENT;
        return -1;
    }

    int ret = %orig;

    if(ret == 0) {
        // Track this symlink in Shadow
        [_shadow addPath:[NSString stringWithUTF8String:path1] toPath:[NSString stringWithUTF8String:path2]];
    }

    return ret;
}

%hookf(int, fstatat, int fd, const char *pathname, struct stat *buf, int flag) {
    if(!pathname) {
        return %orig;
    }

    BOOL restricted = NO;
    char cfdpath[PATH_MAX];
    
    if(fcntl(fd, F_GETPATH, cfdpath) != -1) {
        NSString *fdpath = [NSString stringWithUTF8String:cfdpath];
        NSString *path = [NSString stringWithUTF8String:pathname];

        restricted = [_shadow isPathRestricted:fdpath];

        if(!restricted && [fdpath isEqualToString:@"/"]) {
            restricted = [_shadow isPathRestricted:[NSString stringWithFormat:@"/%@", path]]);
        }
    }

    if(restricted) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}
%end
