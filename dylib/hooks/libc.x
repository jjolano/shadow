#import "hooks.h"

static int (*original_access)(const char* pathname, int mode);
static int replaced_access(const char* pathname, int mode) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_access(pathname, mode);
}

static ssize_t (*original_readlink)(const char* pathname, char* buf, size_t bufsize);
static ssize_t replaced_readlink(const char* pathname, char* buf, size_t bufsize) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_readlink(pathname, buf, bufsize);
}

static ssize_t (*original_readlinkat)(int dirfd, const char* pathname, char* buf, size_t bufsize);
static ssize_t replaced_readlinkat(int dirfd, const char* pathname, char* buf, size_t bufsize) {
    if(pathname
    && dirfd != fileno(stderr)
    && dirfd != fileno(stdout)
    && dirfd != fileno(stdin)) {
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
                path = [pathParent stringByAppendingPathComponent:path];
            }
        }

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            errno = ENOENT;
            return -1;
        }
    }

    return original_readlinkat(dirfd, pathname, buf, bufsize);
}

static int (*original_chdir)(const char* pathname);
static int replaced_chdir(const char* pathname) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_chdir(pathname);
}

static int (*original_fchdir)(int fd);
static int replaced_fchdir(int fd) {
    // Get file descriptor path.
    if(fd != fileno(stderr)
    && fd != fileno(stdout)
    && fd != fileno(stdin)) {
        char pathname[PATH_MAX];

        if(fcntl(fd, F_GETPATH, pathname) != -1) {
            if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
                errno = ENOENT;
                return -1;
            }
        }
    }
    

    return original_fchdir(fd);
}

static int (*original_chroot)(const char* pathname);
static int replaced_chroot(const char* pathname) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }
    
    return original_chroot(pathname);
}

static int (*original_getfsstat)(struct statfs* buf, int bufsize, int flags);
static int replaced_getfsstat(struct statfs* buf, int bufsize, int flags) {
    int result = original_getfsstat(buf, bufsize, flags);

    if(result != -1 && buf) {
        struct statfs* buf_ptr = buf;
        struct statfs* buf_end = buf + sizeof(struct statfs) * result;

        while(buf_ptr < buf_end) {
            if(strcmp(buf_ptr->f_mntonname, "/") == 0) {
                // Mark rootfs read-only
                buf_ptr->f_flags |= MNT_RDONLY | MNT_ROOTFS | MNT_SNAPSHOT;
                break;
            }

            buf_ptr++;
        }
    }

    return result;
}

static int (*original_statfs)(const char* pathname, struct statfs* buf);
static int replaced_statfs(const char* pathname, struct statfs* buf) {
    int result = original_statfs(pathname, buf);

    if(result == 0 && pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            memset(buf, 0, sizeof(struct statfs));
            errno = ENOENT;
            return -1;
        }

        // Modify flags
        if(buf) {
            if(strcmp(buf->f_mntonname, "/") == 0) {
                // Mark rootfs read-only
                buf->f_flags |= MNT_RDONLY | MNT_ROOTFS | MNT_SNAPSHOT;
            }
        }
    }

    return result;
}

static int (*original_fstatfs)(int fd, struct statfs* buf);
static int replaced_fstatfs(int fd, struct statfs* buf) {
    int result = original_fstatfs(fd, buf);

    if(result == 0
    && fd != fileno(stderr)
    && fd != fileno(stdout)
    && fd != fileno(stdin)) {
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
                if(strcmp(buf->f_mntonname, "/") == 0) {
                    // Mark rootfs read-only
                    buf->f_flags |= MNT_RDONLY | MNT_ROOTFS | MNT_SNAPSHOT;
                }
            }
        }
    }

    return result;
}

static int (*original_statvfs)(const char* pathname, struct statvfs* buf);
static int replaced_statvfs(const char* pathname, struct statvfs* buf) {
    int result = original_statvfs(pathname, buf);

    if(result == 0 && pathname) {
        struct statfs st;
        int statfs = replaced_statfs(pathname, &st);

        if(statfs == -1) {
            memset(buf, 0, sizeof(struct statvfs));
            return -1;
        }

        if(strcmp(st.f_mntonname, "/") == 0) {
            // Mark rootfs read-only
            buf->f_flag |= MNT_RDONLY | MNT_ROOTFS | MNT_SNAPSHOT;
        }
    }

    return result;
}

static int (*original_fstatvfs)(int fd, struct statvfs* buf);
static int replaced_fstatvfs(int fd, struct statvfs* buf) {
    int result = original_fstatvfs(fd, buf);

    if(result == 0) {
        struct statfs st;
        int statfs = replaced_fstatfs(fd, &st);

        if(statfs == -1) {
            memset(buf, 0, sizeof(struct statvfs));
            return -1;
        }

        if(strcmp(st.f_mntonname, "/") == 0) {
            // Mark rootfs read-only
            buf->f_flag |= MNT_RDONLY | MNT_ROOTFS | MNT_SNAPSHOT;
        }
    }

    return result;
}

static int (*original_stat)(const char* pathname, struct stat* buf);
static int replaced_stat(const char* pathname, struct stat* buf) {
    int result = original_stat(pathname, buf);
    
    if(result == 0) {
        NSString* path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            memset(buf, 0, sizeof(struct stat));
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

static int (*original_lstat)(const char* pathname, struct stat* buf);
static int replaced_lstat(const char* pathname, struct stat* buf) {
    int result = original_lstat(pathname, buf);

    if(result == 0) {
        NSString* path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        // Only use resolve flag if target is not a symlink.
        if([_shadow isPathRestricted:path resolve:(buf && buf->st_mode & S_IFLNK) ? NO : YES] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            memset(buf, 0, sizeof(struct stat));
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

static int (*original_fstat)(int fd, struct stat* buf);
static int replaced_fstat(int fd, struct stat* buf) {
    int result = original_fstat(fd, buf);

    if(result == 0
    && fd != fileno(stderr)
    && fd != fileno(stdout)
    && fd != fileno(stdin)) {
        // Get file descriptor path.
        char pathname[PATH_MAX];
        NSString* path = nil;

        if(fcntl(fd, F_GETPATH, pathname) != -1) {
            path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

            if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
                errno = EBADF;
                return -1;
            }
        }
    }

    return result;
}

static int (*original_fstatat)(int dirfd, const char* pathname, struct stat* buf, int flags);
static int replaced_fstatat(int dirfd, const char* pathname, struct stat* buf, int flags) {
    int result = original_fstatat(dirfd, pathname, buf, flags);

    if(result == 0 && pathname
    && dirfd != fileno(stderr)
    && dirfd != fileno(stdout)
    && dirfd != fileno(stdin)) {
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
                path = [pathParent stringByAppendingPathComponent:path];
            }
        }

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            memset(buf, 0, sizeof(struct stat));
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

static int (*original_faccessat)(int dirfd, const char* pathname, int mode, int flags);
static int replaced_faccessat(int dirfd, const char* pathname, int mode, int flags) {
    int result = original_faccessat(dirfd, pathname, mode, flags);

    if(result == 0 && pathname
    && dirfd != fileno(stderr)
    && dirfd != fileno(stdout)
    && dirfd != fileno(stdin)) {
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
                path = [pathParent stringByAppendingPathComponent:path];
            }
        }

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

// static int (*original_scandir)(const char* dirname, struct dirent*** namelist, int (*select)(struct dirent *), int (*compar)(const void *, const void *));
// static int replaced_scandir(const char* dirname, struct dirent*** namelist, int (*select)(struct dirent *), int (*compar)(const void *, const void *)) {
//     int result = original_scandir(dirname, namelist, select, compar);

//     return result;
// }

static int (*original_readdir_r)(DIR* dirp, struct dirent* entry, struct dirent** oresult);
static int replaced_readdir_r(DIR* dirp, struct dirent* entry, struct dirent** oresult) {
    int result = original_readdir_r(dirp, entry, oresult);
    
    if(result == 0 && *oresult) {
        int fd = dirfd(dirp);

        // Get file descriptor path.
        char pathname[PATH_MAX];
        NSString* pathParent = nil;

        if(fcntl(fd, F_GETPATH, pathname) != -1) {
            pathParent = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

            do {
                NSString* path = [pathParent stringByAppendingPathComponent:@((*oresult)->d_name)];

                if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
                    // call readdir again to skip ahead
                    result = original_readdir_r(dirp, entry, oresult);
                } else {
                    break;
                }
            } while(result == 0 && *oresult);
        }
    }

    return result;
}

static struct dirent* (*original_readdir)(DIR* dirp);
static struct dirent* replaced_readdir(DIR* dirp) {
    struct dirent* result = original_readdir(dirp);
    
    if(result) {
        int fd = dirfd(dirp);

        // Get file descriptor path.
        char pathname[PATH_MAX];
        NSString* pathParent = nil;

        if(fcntl(fd, F_GETPATH, pathname) != -1) {
            pathParent = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

            do {
                NSString* path = [pathParent stringByAppendingPathComponent:@(result->d_name)];

                if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
                    // call readdir again to skip ahead
                    result = original_readdir(dirp);
                } else {
                    break;
                }
            } while(result);
        }
    }

    return result;
}

static FILE* (*original_fopen)(const char* pathname, const char* mode);
static FILE* replaced_fopen(const char* pathname, const char* mode) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return NULL;
    }

    return original_fopen(pathname, mode);
}

static FILE* (*original_freopen)(const char* pathname, const char* mode, FILE* stream);
static FILE* replaced_freopen(const char* pathname, const char* mode, FILE* stream) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return NULL;
    }

    return original_freopen(pathname, mode, stream);
}

static char* (*original_realpath)(const char* pathname, char* resolved_path);
static char* replaced_realpath(const char* pathname, char* resolved_path) {
    if(([_shadow isCPathRestricted:pathname] || [_shadow isCPathRestricted:resolved_path]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return NULL;
    }

    return original_realpath(pathname, resolved_path);
}

static int (*original_execve)(const char* pathname, char* const argv[], char* const envp[]);
static int replaced_execve(const char* pathname, char* const argv[], char* const envp[]) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_execve(pathname, argv, envp);
}

static int (*original_execvp)(const char* pathname, char* const argv[]);
static int replaced_execvp(const char* pathname, char* const argv[]) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_execvp(pathname, argv);
}

static int (*original_posix_spawn)(pid_t* pid, const char* pathname, const posix_spawn_file_actions_t* file_actions, const posix_spawnattr_t* attrp, char* const argv[], char* const envp[]);
static int replaced_posix_spawn(pid_t* pid, const char* pathname, const posix_spawn_file_actions_t* file_actions, const posix_spawnattr_t* attrp, char* const argv[], char* const envp[]) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_posix_spawn(pid, pathname, file_actions, attrp, argv, envp);
}


static int (*original_posix_spawnp)(pid_t* pid, const char* pathname, const posix_spawn_file_actions_t* file_actions, const posix_spawnattr_t* attrp, char* const argv[], char* const envp[]);
static int replaced_posix_spawnp(pid_t* pid, const char* pathname, const posix_spawn_file_actions_t* file_actions, const posix_spawnattr_t* attrp, char* const argv[], char* const envp[]) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_posix_spawnp(pid, pathname, file_actions, attrp, argv, envp);
}

static int (*original_getattrlist)(const char* path, struct attrlist* attrList, void* attrBuf, size_t attrBufSize, unsigned long options);
static int replaced_getattrlist(const char* path, struct attrlist* attrList, void* attrBuf, size_t attrBufSize, unsigned long options) {
    if([_shadow isCPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_getattrlist(path, attrList, attrBuf, attrBufSize, options);
}

static int (*original_symlink)(const char* path1, const char* path2);
static int replaced_symlink(const char* path1, const char* path2) {
    if([_shadow isCPathRestricted:path2] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = EACCES;
        return -1;
    }

    return original_symlink(path1, path2);
}

static int (*original_link)(const char* path1, const char* path2);
static int replaced_link(const char* path1, const char* path2) {
    if(([_shadow isCPathRestricted:path1] || [_shadow isCPathRestricted:path2]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_link(path1, path2);
}

static int (*original_rename)(const char* old, const char* new);
static int replaced_rename(const char* old, const char* new) {
    if(([_shadow isCPathRestricted:old] || [_shadow isCPathRestricted:new]) && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_rename(old, new);
}

static int (*original_remove)(const char* pathname);
static int replaced_remove(const char* pathname) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_remove(pathname);
}

static int (*original_unlink)(const char* pathname);
static int replaced_unlink(const char* pathname) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_unlink(pathname);
}

static int (*original_unlinkat)(int dirfd, const char* pathname, int flags);
static int replaced_unlinkat(int dirfd, const char* pathname, int flags) {
    if(pathname
    && dirfd != fileno(stderr)
    && dirfd != fileno(stdout)
    && dirfd != fileno(stdin)) {
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
                path = [pathParent stringByAppendingPathComponent:path];
            }
        }

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            errno = ENOENT;
            return -1;
        }
    }

    return original_unlinkat(dirfd, pathname, flags);
}

static int (*original_rmdir)(const char* pathname);
static int replaced_rmdir(const char* pathname) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_rmdir(pathname);
}

static long (*original_pathconf)(const char* pathname, int name);
static long replaced_pathconf(const char* pathname, int name) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_pathconf(pathname, name);
}

static long (*original_fpathconf)(int fd, int name);
static long replaced_fpathconf(int fd, int name) {
    // Get file descriptor path.
    if(fd != fileno(stderr)
    && fd != fileno(stdout)
    && fd != fileno(stdin)) {
        char pathname[PATH_MAX];

        if(fcntl(fd, F_GETPATH, pathname) != -1) {
            if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
                errno = ENOENT;
                return -1;
            }
        }
    }
    

    return original_fpathconf(fd, name);
}

static int (*original_utimes)(const char* pathname, const struct timeval times[2]);
static int replaced_utimes(const char* pathname, const struct timeval times[2]) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_utimes(pathname, times);
}

static int (*original_futimes)(int fd, const struct timeval times[2]);
static int replaced_futimes(int fd, const struct timeval times[2]) {
    // Get file descriptor path.
    if(fd != fileno(stderr)
    && fd != fileno(stdout)
    && fd != fileno(stdin)) {
        char pathname[PATH_MAX];

        if(fcntl(fd, F_GETPATH, pathname) != -1) {
            if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
                errno = ENOENT;
                return -1;
            }
        }
    }
    

    return original_futimes(fd, times);
}

static char* (*original_getenv)(const char* name);
static char* replaced_getenv(const char* name) {
    char* result = original_getenv(name);

    if(result && name) {
        if(strcmp(name, "DYLD_INSERT_LIBRARIES") == 0
        || strcmp(name, "_MSSafeMode") == 0
        || strcmp(name, "_SafeMode") == 0
        || strcmp(name, "_SubstituteSafeMode") == 0
        || strcmp(name, "SHELL") == 0) {
            return NULL;
        }
    }

    return result;
}

static int (*original_ptrace)(int _request, pid_t _pid, caddr_t _addr, int _data);
static int replaced_ptrace(int _request, pid_t _pid, caddr_t _addr, int _data) {
    if(_request == PT_DENY_ATTACH) {
        return 0;
    }

    return original_ptrace(_request, _pid, _addr, _data);
}

static int (*original_sysctl)(int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen);
static int replaced_sysctl(int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen) {
    if(namelen == 4
    && name[0] == CTL_KERN
    && name[1] == KERN_PROC
    && name[2] == KERN_PROC_ALL
    && name[3] == 0) {
        // Running process check.
        *oldlenp = 0;
        return 0;
    }

    int ret = original_sysctl(name, namelen, oldp, oldlenp, newp, newlen);

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

static pid_t replaced_getppid() {
    return 1;
}

static int (*original_open)(const char *pathname, int oflag, ...);
static int replaced_open(const char *pathname, int oflag, ...) {
    void* arg;
    va_list args;
    va_start(args, oflag);
    arg = va_arg(args, void *);
    va_end(args);

    int result = original_open(pathname, oflag, arg);

    if(result != -1) {
        char fd_pathname[PATH_MAX];
        fcntl(result, F_GETPATH, fd_pathname);

        if([_shadow isCPathRestricted:fd_pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            close(result);
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

static int (*original_openat)(int dirfd, const char *pathname, int oflag, ...);
static int replaced_openat(int dirfd, const char *pathname, int oflag, ...) {
    void* arg;
    va_list args;
    va_start(args, oflag);
    arg = va_arg(args, void *);
    va_end(args);

    int result = original_openat(dirfd, pathname, oflag, arg);

    if(result != -1) {
        char fd_pathname[PATH_MAX];
        fcntl(result, F_GETPATH, fd_pathname);

        if([_shadow isCPathRestricted:fd_pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            close(result);
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

static DIR* (*original___opendir2)(const char* pathname, size_t bufsize);
static DIR* replaced___opendir2(const char* pathname, size_t bufsize) {
    DIR* result = original___opendir2(pathname, bufsize);

    if(result) {
        int fd = dirfd(result);

        char fd_pathname[PATH_MAX];
        fcntl(fd, F_GETPATH, fd_pathname);

        if([_shadow isCPathRestricted:fd_pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            closedir(result);
            errno = ENOENT;
            return NULL;
        }
    }

    return result;
}

void shadowhook_libc(HKBatchHook* hooks) {
    [hooks addFunctionHook:access withReplacement:replaced_access outOldPtr:(void **) &original_access];
    [hooks addFunctionHook:chdir withReplacement:replaced_chdir outOldPtr:(void **) &original_chdir];
    [hooks addFunctionHook:chroot withReplacement:replaced_chroot outOldPtr:(void **) &original_chroot];
    [hooks addFunctionHook:statfs withReplacement:replaced_statfs outOldPtr:(void **) &original_statfs];
    [hooks addFunctionHook:fstatfs withReplacement:replaced_fstatfs outOldPtr:(void **) &original_fstatfs];
    [hooks addFunctionHook:statvfs withReplacement:replaced_statvfs outOldPtr:(void **) &original_statvfs];
    [hooks addFunctionHook:fstatvfs withReplacement:replaced_fstatvfs outOldPtr:(void **) &original_fstatvfs];
    [hooks addFunctionHook:stat withReplacement:replaced_stat outOldPtr:(void **) &original_stat];
    [hooks addFunctionHook:lstat withReplacement:replaced_lstat outOldPtr:(void **) &original_lstat];
    [hooks addFunctionHook:faccessat withReplacement:replaced_faccessat outOldPtr:(void **) &original_faccessat];
    [hooks addFunctionHook:readdir_r withReplacement:replaced_readdir_r outOldPtr:(void **) &original_readdir_r];
    [hooks addFunctionHook:readdir withReplacement:replaced_readdir outOldPtr:(void **) &original_readdir];
    [hooks addFunctionHook:fopen withReplacement:replaced_fopen outOldPtr:(void **) &original_fopen];
    [hooks addFunctionHook:freopen withReplacement:replaced_freopen outOldPtr:(void **) &original_freopen];
    [hooks addFunctionHook:realpath withReplacement:replaced_realpath outOldPtr:(void **) &original_realpath];
    [hooks addFunctionHook:readlink withReplacement:replaced_readlink outOldPtr:(void **) &original_readlink];
    [hooks addFunctionHook:readlinkat withReplacement:replaced_readlinkat outOldPtr:(void **) &original_readlinkat];
    [hooks addFunctionHook:link withReplacement:replaced_link outOldPtr:(void **) &original_link];
    // [hooks addFunctionHook:scandir withReplacement:replaced_scandir outOldPtr:(void **) &original_scandir];

    [_shadow setOrigFunc:@"access" withAddr:original_access];
    [_shadow setOrigFunc:@"lstat" withAddr:original_lstat];
}

void shadowhook_libc_extra(HKBatchHook* hooks) {
    [hooks addFunctionHook:fstat withReplacement:replaced_fstat outOldPtr:(void **) &original_fstat];
    [hooks addFunctionHook:fstatat withReplacement:replaced_fstatat outOldPtr:(void **) &original_fstatat];
    [hooks addFunctionHook:execve withReplacement:replaced_execve outOldPtr:(void **) &original_execve];
    [hooks addFunctionHook:execvp withReplacement:replaced_execvp outOldPtr:(void **) &original_execvp];
    [hooks addFunctionHook:posix_spawn withReplacement:replaced_posix_spawn outOldPtr:(void **) &original_posix_spawn];
    [hooks addFunctionHook:posix_spawnp withReplacement:replaced_posix_spawnp outOldPtr:(void **) &original_posix_spawnp];
    [hooks addFunctionHook:getattrlist withReplacement:replaced_getattrlist outOldPtr:(void **) &original_getattrlist];
    [hooks addFunctionHook:symlink withReplacement:replaced_symlink outOldPtr:(void **) &original_symlink];
    [hooks addFunctionHook:rename withReplacement:replaced_rename outOldPtr:(void **) &original_rename];
    [hooks addFunctionHook:remove withReplacement:replaced_remove outOldPtr:(void **) &original_remove];
    [hooks addFunctionHook:unlink withReplacement:replaced_unlink outOldPtr:(void **) &original_unlink];
    [hooks addFunctionHook:unlinkat withReplacement:replaced_unlinkat outOldPtr:(void **) &original_unlinkat];
    [hooks addFunctionHook:rmdir withReplacement:replaced_rmdir outOldPtr:(void **) &original_rmdir];
    [hooks addFunctionHook:pathconf withReplacement:replaced_pathconf outOldPtr:(void **) &original_pathconf];
    [hooks addFunctionHook:fpathconf withReplacement:replaced_fpathconf outOldPtr:(void **) &original_fpathconf];
    [hooks addFunctionHook:utimes withReplacement:replaced_utimes outOldPtr:(void **) &original_utimes];
    [hooks addFunctionHook:futimes withReplacement:replaced_futimes outOldPtr:(void **) &original_futimes];
    [hooks addFunctionHook:fchdir withReplacement:replaced_fchdir outOldPtr:(void **) &original_fchdir];
    [hooks addFunctionHook:getfsstat withReplacement:replaced_getfsstat outOldPtr:(void **) &original_getfsstat];
}

void shadowhook_libc_envvar(HKBatchHook* hooks) {
    [hooks addFunctionHook:getenv withReplacement:replaced_getenv outOldPtr:(void **) &original_getenv];
}

void shadowhook_libc_lowlevel(HKBatchHook* hooks) {
    [hooks addFunctionHook:open withReplacement:replaced_open outOldPtr:(void **) &original_open];
    [hooks addFunctionHook:openat withReplacement:replaced_openat outOldPtr:(void **) &original_openat];
    [hooks addFunctionHook:__opendir2 withReplacement:replaced___opendir2 outOldPtr:(void **) &original___opendir2];
}

void shadowhook_libc_antidebugging(HKBatchHook* hooks) {
    [hooks addFunctionHook:ptrace withReplacement:replaced_ptrace outOldPtr:(void **) &original_ptrace];
    [hooks addFunctionHook:sysctl withReplacement:replaced_sysctl outOldPtr:(void **) &original_sysctl];
    [hooks addFunctionHook:getppid withReplacement:replaced_getppid outOldPtr:NULL];
}
