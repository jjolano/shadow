#import "hooks.h"

%group shadowhook_libc
%hookf(int, access, const char *pathname, int mode) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, statfs, const char *pathname, struct statfs *buf) {
    int ret = %orig;

    if(pathname && ret == 0) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }

        // Modify flags
        if(buf) {
            if([path hasPrefix:@"/var"]
            || [path hasPrefix:@"/private/var"]) {
                buf->f_flags |= MNT_NOSUID | MNT_NODEV;
            } else {
                buf->f_flags |= MNT_RDONLY | MNT_ROOTFS;
            }
        }
    }

    return ret;
}

%hookf(int, stat, const char *pathname, struct stat *statbuf) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, lstat, const char *pathname, struct stat *statbuf) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(FILE *, fopen, const char *pathname, const char *mode) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return NULL;
        }
    }

    return %orig;
}

%hookf(FILE *, freopen, const char *pathname, const char *mode, FILE *stream) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return NULL;
        }
    }

    return %orig;
}

%hookf(char *, getenv, const char *name) {
    if(name) {
        NSString *env = [NSString stringWithUTF8String:name];

        if([env isEqualToString:@"DYLD_INSERT_LIBRARIES"]
        || [env isEqualToString:@"_MSSafeMode"]
        || [env isEqualToString:@"_SafeMode"]) {
            return NULL;
        }
    }

    return %orig;
}

%hookf(char *, realpath, const char *pathname, char *resolved_path) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return NULL;
        }
    }

    return %orig;
}

%hookf(DIR *, opendir, const char *pathname) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return NULL;
        }
    }

    return %orig;
}

// %hookf(int, fstat, int fd, struct stat *buf) {
//     char fdpath[PATH_MAX];

//     if(fcntl(fd, F_GETPATH, fdpath) != -1) {
//         NSString *fd_path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:fdpath length:strlen(fdpath)];

//         if([_shadow isPathRestricted:fd_path]) {
//             errno = EBADF;
//             return -1;
//         }
//     }

//     return %orig;
// }

// %hookf(int, open, const char *pathname, int oflag, ...) {
//     if(pathname) {
//         NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

//         if([_shadow isPathRestricted:path]) {
//             errno = ENOENT;
//             return -1;
//         }
//     }

//     if(oflag & O_CREAT) {
//         mode_t mode;
//         va_list args;
//         va_start(args, oflag);
//         mode = (mode_t) va_arg(args, int);
//         va_end(args);

//         return %orig(pathname, oflag, mode);
//     }

//     return %orig(pathname, oflag);
// }

%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int ret = %orig;

    if(ops == CS_OPS_STATUS && (ret & CS_PLATFORM_BINARY) == CS_PLATFORM_BINARY && pid == getpid()) {
        // Ensure that the platform binary flag is not set.
        ret &= ~CS_PLATFORM_BINARY;
    }

    return ret;
}

%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if(namelen == 4
    && name[0] == CTL_KERN
    && name[1] == KERN_PROC
    && name[2] == KERN_PROC_ALL
    && name[3] == 0) {
        // Running process check.
        *oldlenp = 0;
        return 0;
    }

    int ret = %orig;

    if(ret == 0
    && name[0] == CTL_KERN
    && name[1] == KERN_PROC
    && name[2] == KERN_PROC_PID
    && name[3] == getpid()) {
        // Remove trace flag.
        if(oldp) {
            struct kinfo_proc *p = ((struct kinfo_proc *) oldp);

            if((p->kp_proc.p_flag & P_TRACED) == P_TRACED) {
                p->kp_proc.p_flag &= ~P_TRACED;
            }
        }
    }

    return ret;
}

%hookf(pid_t, getppid) {
    return 1;
}
%end

static int (*original_open)(const char *pathname, int oflag, ...);
static int replaced_open(const char *pathname, int oflag, ...) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    if(oflag & O_CREAT) {
        mode_t mode;
        va_list args;
        va_start(args, oflag);
        mode = (mode_t) va_arg(args, int);
        va_end(args);

        return original_open(pathname, oflag, mode);
    }

    return original_open(pathname, oflag);
}

void shadowhook_libc(void) {
    %init(shadowhook_libc);

    // Manual hooks
    MSHookFunction(open, replaced_open, (void **) &original_open);
}
