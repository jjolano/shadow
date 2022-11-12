#import "hooks.h"

%group shadowhook_libc
%hookf(int, access, const char *pathname, int mode) {
    int result = %orig;

    if(result == 0) {
        if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

%hookf(ssize_t, readlink, const char* pathname, char* buf, size_t bufsize) {
    ssize_t result = %orig;
    
    if(result != -1) {
        if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            *buf = '\0';
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

%hookf(ssize_t, readlinkat, int dirfd, const char* pathname, char* buf, size_t bufsize) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if(![path isAbsolutePath]) {
            // Get file descriptor path.
            char pathnameParent[PATH_MAX];
            NSString* pathParent = nil;

            if(dirfd == AT_FDCWD) {
                pathParent = [[NSFileManager defaultManager] currentDirectoryPath];
            } else if(fcntl(dirfd, F_GETPATH, pathnameParent) != -1) {
                pathParent = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathnameParent length:strlen(pathnameParent)];
            }

            if(pathParent) {
                NSMutableArray* pathComponents = [[pathParent pathComponents] mutableCopy];
                [pathComponents addObject:@(pathname)];

                path = [NSString pathWithComponents:pathComponents];
            }
        }

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            *buf = '\0';
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, chdir, const char *pathname) {
    int result = %orig;

    if(result == 0) {
        if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

%hookf(int, fchdir, int fd) {
    int result = %orig;

    if(result == 0) {
        // Get file descriptor path.
        char pathname[PATH_MAX];

        if(fcntl(fd, F_GETPATH, pathname) != -1) {
            if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
                errno = ENOENT;
                return -1;
            }
        }
    }

    return result;
}

%hookf(int, chroot, const char *pathname) {
    int result = %orig;

    if(result == 0) {
        if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

%hookf(int, statfs, const char *pathname, struct statfs *buf) {
    int result = %orig;

    if(result == 0 && pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            memset(buf, 0, sizeof(struct statfs));
            errno = ENOENT;
            return -1;
        }

        // Modify flags
        if(buf) {
            path = [_shadow resolvePath:path];

            if([path hasPrefix:@"/var"]
            || [path hasPrefix:@"/private/var"]
            || [path hasPrefix:@"/private/preboot"]) {
                buf->f_flags |= MNT_NOSUID | MNT_NODEV;
            } else {
                buf->f_flags |= MNT_RDONLY | MNT_ROOTFS;
            }
        }
    }

    return result;
}

%hookf(int, fstatfs, int fd, struct statfs *buf) {
    int result = %orig;

    if(result == 0) {
        // Get file descriptor path.
        char pathname[PATH_MAX];
        NSString* path = nil;

        if(fcntl(fd, F_GETPATH, pathname) != -1) {
            path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

            if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
                memset(buf, 0, sizeof(struct statfs));
                errno = ENOENT;
                return -1;
            }

            // Modify flags
            if(buf) {
                path = [_shadow resolvePath:path];

                if([path hasPrefix:@"/var"]
                || [path hasPrefix:@"/private/var"]
                || [path hasPrefix:@"/private/preboot"]) {
                    buf->f_flags |= MNT_NOSUID | MNT_NODEV;
                } else {
                    buf->f_flags |= MNT_RDONLY | MNT_ROOTFS;
                }
            }
        }
    }

    return result;
}

%hookf(int, stat, const char *pathname, struct stat *buf) {
    int result = %orig;
    
    if(result == 0) {
        NSString* path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            memset(buf, 0, sizeof(struct stat));
            errno = ENOENT;
            return -1;
        }

        if(buf) {
            path = [_shadow resolvePath:path];

            if([path isEqualToString:@"/Applications"]) {
                buf->st_mode &= ~S_IFLNK;
                buf->st_mode |= S_IFDIR;
            }

            if([path isEqualToString:@"/bin"]) {
                if(buf->st_size > 128) {
                    buf->st_size = 128;
                }
            }
        }
    }

    return result;
}

%hookf(int, lstat, const char *pathname, struct stat *buf) {
    int result = %orig;

    if(result == 0) {
        NSString* path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path resolve:NO] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            memset(buf, 0, sizeof(struct stat));
            errno = ENOENT;
            return -1;
        }

        if(buf) {
            path = [_shadow resolvePath:path];

            if([path isEqualToString:@"/Applications"]) {
                buf->st_mode &= ~S_IFLNK;
                buf->st_mode |= S_IFDIR;
            }

            if([path isEqualToString:@"/bin"]) {
                if(buf->st_size > 128) {
                    buf->st_size = 128;
                }
            }
        }
    }

    return result;
}

// %hookf(int, fstat, int fd, struct stat *buf) {
//     int result = %orig;

//     if(result == 0) {
//         // Get file descriptor path.
//         char pathname[PATH_MAX];
//         NSString* path = nil;

//         if(fcntl(fd, F_GETPATH, pathname) != -1) {
//             path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

//             if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
//                 errno = EBADF;
//                 return -1;
//             }

//             if(buf) {
//                 if([path isEqualToString:@"/bin"]) {
//                     if(buf->st_size > 128) {
//                         buf->st_size = 128;
//                     }
//                 }
//             }
//         }
//     }

//     return result;
// }

%hookf(int, fstatat, int dirfd, const char *pathname, struct stat *buf, int flags) {
    int result = %orig;

    if(result == 0 && pathname) {
        NSString* path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if(![path isAbsolutePath]) {
            // Get file descriptor path.
            char pathnameParent[PATH_MAX];
            NSString* pathParent = nil;

            if(dirfd == AT_FDCWD) {
                pathParent = [[NSFileManager defaultManager] currentDirectoryPath];
            } else if(fcntl(dirfd, F_GETPATH, pathnameParent) != -1) {
                pathParent = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathnameParent length:strlen(pathnameParent)];
            }

            if(pathParent) {
                NSMutableArray* pathComponents = [[pathParent pathComponents] mutableCopy];
                [pathComponents addObject:@(pathname)];

                path = [NSString pathWithComponents:pathComponents];
            }
        }

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            memset(buf, 0, sizeof(struct stat));
            errno = ENOENT;
            return -1;
        }

        if(buf) {
            path = [_shadow resolvePath:path];

            if([path isEqualToString:@"/Applications"]) {
                buf->st_mode &= ~S_IFLNK;
                buf->st_mode |= S_IFDIR;
            }

            if([path isEqualToString:@"/bin"]) {
                if(buf->st_size > 128) {
                    buf->st_size = 128;
                }
            }
        }
    }

    return result;
}

%hookf(int, faccessat, int dirfd, const char *pathname, int mode, int flags) {
    int result = %orig;

    if(result == 0 && pathname) {
        NSString* path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if(![path isAbsolutePath]) {
            // Get file descriptor path.
            char pathnameParent[PATH_MAX];
            NSString* pathParent = nil;

            if(dirfd == AT_FDCWD) {
                pathParent = [[NSFileManager defaultManager] currentDirectoryPath];
            } else if(fcntl(dirfd, F_GETPATH, pathnameParent) != -1) {
                pathParent = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathnameParent length:strlen(pathnameParent)];
            }

            if(pathParent) {
                NSMutableArray* pathComponents = [[pathParent pathComponents] mutableCopy];
                [pathComponents addObject:@(pathname)];

                path = [NSString pathWithComponents:pathComponents];
            }
        }

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

%hookf(int, readdir_r, DIR *restrict dirp, struct dirent *restrict entry, struct dirent **restrict oresult) {
    int result = %orig;
    
    if(result == 0 && *oresult) {
        int fd = dirfd(dirp);

        do {
            // Get file descriptor path.
            char pathname[PATH_MAX];
            NSString* pathParent = nil;

            if(fcntl(fd, F_GETPATH, pathname) != -1) {
                pathParent = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

                NSMutableArray* pathComponents = [[pathParent pathComponents] mutableCopy];
                [pathComponents addObject:@(entry->d_name)];

                NSString* path = [NSString pathWithComponents:pathComponents];

                if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
                    // call readdir again to skip ahead
                    result = %orig;
                } else {
                    break;
                }
            }
        } while(result == 0 && *oresult);
    }

    return result;
}

%hookf(struct dirent *, readdir, DIR* dirp) {
    struct dirent* result = %orig;
    
    if(result) {
        int fd = dirfd(dirp);

        do {
            // Get file descriptor path.
            char pathname[PATH_MAX];
            NSString* pathParent = nil;

            if(fcntl(fd, F_GETPATH, pathname) != -1) {
                pathParent = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

                NSMutableArray* pathComponents = [[pathParent pathComponents] mutableCopy];
                [pathComponents addObject:@(result->d_name)];

                NSString* path = [NSString pathWithComponents:pathComponents];

                if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
                    // call readdir again to skip ahead
                    result = %orig;
                } else {
                    break;
                }
            }
        } while(result);
    }

    return result;
}

%hookf(FILE *, fopen, const char *pathname, const char *mode) {
    FILE* result = %orig;

    if(result) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            fclose(result);
            errno = ENOENT;
            return NULL;
        }
    }

    return result;
}

%hookf(FILE *, freopen, const char *pathname, const char *mode, FILE *stream) {
    FILE* result = %orig;
    
    if(result && pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            fclose(result);
            errno = ENOENT;
            return NULL;
        }
    }

    return result;
}

%hookf(char *, realpath, const char *pathname, char *resolved_path) {
    char* result = %orig;
    
    if(result) {
        if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            errno = ENOENT;
            return NULL;
        }
    }

    return result;
}

%hookf(int, execve, const char *pathname, char *const argv[], char *const envp[]) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}

%hookf(int, execvp, const char *pathname, char *const argv[]) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}

%hookf(int, posix_spawn, pid_t *pid, const char *pathname, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}

%hookf(int, posix_spawnp, pid_t *pid, const char *pathname, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}

%hookf(int, getattrlist, const char* path, struct attrlist* attrList, void* attrBuf, size_t attrBufSize, unsigned long options) {
    int result = %orig;
    
    if(result == 0) {
        if([_shadow isCPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

%hookf(int, symlink, const char* path1, const char* path2) {
    if([_shadow isCPathRestricted:path2] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = EACCES;
        return -1;
    }

    return %orig;
}

%hookf(int, link, const char* path1, const char* path2) {
    if(([_shadow isCPathRestricted:path1] || [_shadow isCPathRestricted:path2]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}

%hookf(int, rename, const char* old, const char* new) {
    if(([_shadow isCPathRestricted:old] || [_shadow isCPathRestricted:new]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}

%hookf(int, remove, const char* pathname) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}

%hookf(int, unlink, const char* pathname) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}

%hookf(int, unlinkat, int dirfd, const char* pathname, int flags) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if(![path isAbsolutePath]) {
            // Get file descriptor path.
            char pathnameParent[PATH_MAX];
            NSString* pathParent = nil;

            if(dirfd == AT_FDCWD) {
                pathParent = [[NSFileManager defaultManager] currentDirectoryPath];
            } else if(fcntl(dirfd, F_GETPATH, pathnameParent) != -1) {
                pathParent = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathnameParent length:strlen(pathnameParent)];
            }

            if(pathParent) {
                NSMutableArray* pathComponents = [[pathParent pathComponents] mutableCopy];
                [pathComponents addObject:@(pathname)];

                path = [NSString pathWithComponents:pathComponents];
            }
        }

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, rmdir, const char* pathname) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return %orig;
}
%end

%group shadowhook_libc_env
%hookf(char *, getenv, const char *name) {
    if(name) {
        NSString *env = [NSString stringWithUTF8String:name];

        if([env isEqualToString:@"DYLD_INSERT_LIBRARIES"]
        || [env isEqualToString:@"_MSSafeMode"]
        || [env isEqualToString:@"_SafeMode"]
        || [env isEqualToString:@"SHELL"]) {
            return NULL;
        }
        /*
        if([env isEqualToString:@"SIMULATOR_MODEL_IDENTIFIER"]) {
            struct utsname systemInfo;
            uname(&systemInfo);

            return (char *)[@(systemInfo.machine) UTF8String];
        }
        */
    }

    return %orig;
}
%end

%group shadowhook_libc_debug
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

%hookf(int, isatty, int fd) {
    errno = ENOTTY;
    return 0;
}
%end

static int (*original_open)(const char *pathname, int oflag, ...);
static int replaced_open(const char *pathname, int oflag, ...) {
    int result = -1;

    if(oflag & O_CREAT) {
        mode_t mode;
        va_list args;
        va_start(args, oflag);
        mode = (mode_t) va_arg(args, int);
        va_end(args);

        result = original_open(pathname, oflag, mode);
    } else {
        result = original_open(pathname, oflag);
    }

    if(result != -1 && pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            close(result);
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

static int (*original_openat)(int dirfd, const char *pathname, int oflag, ...);
static int replaced_openat(int dirfd, const char *pathname, int oflag, ...) {
    int result = -1;

    if(oflag & O_CREAT) {
        mode_t mode;
        va_list args;
        va_start(args, oflag);
        mode = (mode_t) va_arg(args, int);
        va_end(args);

        result = original_openat(dirfd, pathname, oflag, mode);
    } else {
        result = original_openat(dirfd, pathname, oflag);
    }

    if(result != -1 && pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if(![path isAbsolutePath]) {
            // Get file descriptor path.
            char pathnameParent[PATH_MAX];
            NSString* pathParent = nil;

            if(dirfd == AT_FDCWD) {
                pathParent = [[NSFileManager defaultManager] currentDirectoryPath];
            } else if(fcntl(dirfd, F_GETPATH, pathnameParent) != -1) {
                pathParent = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathnameParent length:strlen(pathnameParent)];
            }

            if(pathParent) {
                NSMutableArray* pathComponents = [[pathParent pathComponents] mutableCopy];
                [pathComponents addObject:@(pathname)];

                path = [NSString pathWithComponents:pathComponents];
            }
        }

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            close(result);
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

/*
static int (*original_syscall)(int number, ...);
static int replaced_syscall(int number, ...) {
    HBLogDebug(@"%@: %d", @"syscall", number);

    char* stack[8];
	va_list args;
	va_start(args, number);

    #if defined __arm64__ || defined __arm64e__
	memcpy(stack, args, 64);
    #endif

    #if defined __armv7__ || defined __armv7s__
	memcpy(stack, args, 32);
    #endif

    // Get pathname from arguments for later

    va_end(args);

    int result = original_syscall(number, stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7]);

    if(result == 0) {
        // Handle if syscall is successful
    }

    return result;
}
*/

%group shadowhook_libc_opendir
// %hookf(DIR *, opendir, const char *pathname) {
//     DIR* result = %orig;
    
//     if(result && pathname) {
//         NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

//         if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
//             errno = ENOENT;
//             return NULL;
//         }
//     }

//     return result;
// }

%hookf(DIR *, __opendir2, const char *pathname, size_t bufsize) {
    DIR* result = %orig;
    
    if(result) {
        if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            closedir(result);
            errno = ENOENT;
            return NULL;
        }
    }

    return result;
}
%end

void shadowhook_libc(void) {
    %init(shadowhook_libc);

    // MSHookFunction(syscall, replaced_syscall, (void **) &original_syscall);
    // MSHookFunction(__opendir2, replaced_opendir2, (void **) &original_opendir2);
}

void shadowhook_libc_envvar(void) {
    %init(shadowhook_libc_env);
}

void shadowhook_libc_lowlevel(void) {
    %init(shadowhook_libc_opendir);
    MSHookFunction(open, replaced_open, (void **) &original_open);
    MSHookFunction(openat, replaced_openat, (void **) &original_openat);
}

void shadowhook_libc_antidebugging(void) {
    %init(shadowhook_libc_debug);
}
