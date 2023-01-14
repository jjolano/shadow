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
        || strcmp(name, "_SubstituteSafeMode") == 0) {
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

// static pid_t replaced_fork() {
//     errno = ENOSYS;
//     return -1;
// }

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

void shadowhook_libc(HKSubstitutor* hooks) {
    MSHookFunction(access, replaced_access, (void **) &original_access);
    MSHookFunction(chdir, replaced_chdir, (void **) &original_chdir);
    MSHookFunction(chroot, replaced_chroot, (void **) &original_chroot);
    MSHookFunction(statfs, replaced_statfs, (void **) &original_statfs);
    MSHookFunction(fstatfs, replaced_fstatfs, (void **) &original_fstatfs);
    MSHookFunction(statvfs, replaced_statvfs, (void **) &original_statvfs);
    MSHookFunction(fstatvfs, replaced_fstatvfs, (void **) &original_fstatvfs);
    MSHookFunction(stat, replaced_stat, (void **) &original_stat);
    MSHookFunction(lstat, replaced_lstat, (void **) &original_lstat);
    MSHookFunction(faccessat, replaced_faccessat, (void **) &original_faccessat);
    MSHookFunction(readdir_r, replaced_readdir_r, (void **) &original_readdir_r);
    MSHookFunction(readdir, replaced_readdir, (void **) &original_readdir);
    MSHookFunction(fopen, replaced_fopen, (void **) &original_fopen);
    MSHookFunction(freopen, replaced_freopen, (void **) &original_freopen);
    MSHookFunction(realpath, replaced_realpath, (void **) &original_realpath);
    MSHookFunction(readlink, replaced_readlink, (void **) &original_readlink);
    MSHookFunction(readlinkat, replaced_readlinkat, (void **) &original_readlinkat);
    MSHookFunction(link, replaced_link, (void **) &original_link);
    // MSHookFunction(scandir, replaced_scandir, (void **) &original_scandir);

    [_shadow setOrigFunc:@"access" withAddr:(void **) &original_access];
    [_shadow setOrigFunc:@"lstat" withAddr:(void **) &original_lstat];
}

void shadowhook_libc_extra(HKSubstitutor* hooks) {
    MSHookFunction(fstat, replaced_fstat, (void **) &original_fstat);
    MSHookFunction(fstatat, replaced_fstatat, (void **) &original_fstatat);
    MSHookFunction(execve, replaced_execve, (void **) &original_execve);
    MSHookFunction(execvp, replaced_execvp, (void **) &original_execvp);
    MSHookFunction(posix_spawn, replaced_posix_spawn, (void **) &original_posix_spawn);
    MSHookFunction(posix_spawnp, replaced_posix_spawnp, (void **) &original_posix_spawnp);
    MSHookFunction(getattrlist, replaced_getattrlist, (void **) &original_getattrlist);
    MSHookFunction(symlink, replaced_symlink, (void **) &original_symlink);
    MSHookFunction(rename, replaced_rename, (void **) &original_rename);
    MSHookFunction(remove, replaced_remove, (void **) &original_remove);
    MSHookFunction(unlink, replaced_unlink, (void **) &original_unlink);
    MSHookFunction(unlinkat, replaced_unlinkat, (void **) &original_unlinkat);
    MSHookFunction(rmdir, replaced_rmdir, (void **) &original_rmdir);
    MSHookFunction(pathconf, replaced_pathconf, (void **) &original_pathconf);
    MSHookFunction(fpathconf, replaced_fpathconf, (void **) &original_fpathconf);
    MSHookFunction(utimes, replaced_utimes, (void **) &original_utimes);
    MSHookFunction(futimes, replaced_futimes, (void **) &original_futimes);
    MSHookFunction(fchdir, replaced_fchdir, (void **) &original_fchdir);
    MSHookFunction(getfsstat, replaced_getfsstat, (void **) &original_getfsstat);
}

void shadowhook_libc_envvar(HKSubstitutor* hooks) {
    MSHookFunction(getenv, replaced_getenv, (void **) &original_getenv);
}

void shadowhook_libc_lowlevel(HKSubstitutor* hooks) {
    MSHookFunction(open, replaced_open, (void **) &original_open);
    MSHookFunction(openat, replaced_openat, (void **) &original_openat);
    MSHookFunction(__opendir2, replaced___opendir2, (void **) &original___opendir2);
}

void shadowhook_libc_antidebugging(HKSubstitutor* hooks) {
    MSHookFunction(ptrace, replaced_ptrace, (void **) &original_ptrace);
    MSHookFunction(sysctl, replaced_sysctl, (void **) &original_sysctl);
    MSHookFunction(getppid, replaced_getppid, NULL);
    // MSHookFunction(fork, replaced_fork, NULL);
}
