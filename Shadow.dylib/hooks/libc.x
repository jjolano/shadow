#import "hooks.h"

static int (*original_access)(const char* pathname, int mode);
static int replaced_access(const char* pathname, int mode) {
    int result = original_access(pathname, mode);

    if(result != -1 && !isCallerTweak() && [_shadow isCPathRestricted:pathname]) {
        errno = ENOENT;
        return -1;
    }

    return result;
}

static ssize_t (*original_readlink)(const char* pathname, char* buf, size_t bufsize);
static ssize_t replaced_readlink(const char* pathname, char* buf, size_t bufsize) {
    ssize_t result = original_readlink(pathname, buf, bufsize);

    if(result != -1 && !isCallerTweak() && [_shadow isCPathRestricted:pathname]) {
        errno = ENOENT;
        return -1;
    }

    return result;
}

static ssize_t (*original_readlinkat)(int dirfd, const char* pathname, char* buf, size_t bufsize);
static ssize_t replaced_readlinkat(int dirfd, const char* pathname, char* buf, size_t bufsize) {
    if(isCallerTweak()) {
        return original_readlinkat(dirfd, pathname, buf, bufsize);
    }

    if(pathname
    && dirfd != fileno(stderr)
    && dirfd != fileno(stdout)
    && dirfd != fileno(stdin)) {
        NSString* path = [NSString stringWithUTF8String:pathname];

        // Get file descriptor path.
        char pathnameParent[PATH_MAX];
        NSString* pathParent = nil;

        if(dirfd == AT_FDCWD) {
            pathParent = [[NSFileManager defaultManager] currentDirectoryPath];
        } else if(fcntl(dirfd, F_GETPATH, pathnameParent) != -1) {
            pathParent = [NSString stringWithUTF8String:pathnameParent];
        }

        if([_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : pathParent}]) {
            errno = [path isAbsolutePath] ? ENOENT : EBADF;
            return -1;
        }
    }

    return original_readlinkat(dirfd, pathname, buf, bufsize);
}

static int (*original_chdir)(const char* pathname);
static int replaced_chdir(const char* pathname) {
    if(isCallerTweak() || ![_shadow isCPathRestricted:pathname]) {
        return original_chdir(pathname);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_fchdir)(int fd);
static int replaced_fchdir(int fd) {
    if(isCallerTweak()) {
        return original_fchdir(fd);
    }

    // Get file descriptor path.
    if(fd != fileno(stderr)
    && fd != fileno(stdout)
    && fd != fileno(stdin)) {
        char pathname[PATH_MAX];

        if(fcntl(fd, F_GETPATH, pathname) != -1 && [_shadow isCPathRestricted:pathname]) {
            errno = EBADF;
            return -1;
        }
    }

    return original_fchdir(fd);
}

static int (*original_chroot)(const char* pathname);
static int replaced_chroot(const char* pathname) {
    if(isCallerTweak() || ![_shadow isCPathRestricted:pathname]) {
        return original_chroot(pathname);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_creat)(const char* pathname, mode_t mode);
static int replaced_creat(const char* pathname, mode_t mode) {
    if(isCallerTweak() || ![_shadow isCPathRestricted:pathname]) {
        return original_creat(pathname, mode);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_getfsstat)(struct statfs* buf, int bufsize, int flags);
static int replaced_getfsstat(struct statfs* buf, int bufsize, int flags) {
    if(isCallerTweak()) {
        return original_getfsstat(buf, bufsize, flags);
    }

    int result = original_getfsstat(buf, bufsize, flags);

    if(result != -1 && buf) {
        struct statfs* buf_ptr = buf;
        struct statfs* buf_end = buf + sizeof(struct statfs) * result;

        while(buf_ptr < buf_end) {
            if([_shadow isCPathRestricted:buf_ptr->f_mntonname]) {
                // handle bindfs/chroot
                strcpy(buf_ptr->f_mntonname, "/");
            }

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

static int (*original_getmntinfo)(struct statfs** mntbufp, int flags);
static int replaced_getmntinfo(struct statfs** mntbufp, int flags) {
    if(isCallerTweak()) {
        return original_getmntinfo(mntbufp, flags);
    }

    int result = original_getmntinfo(mntbufp, flags);

    if(result > 0) {
        struct statfs** buf_ptr = mntbufp;
        struct statfs** buf_end = mntbufp + sizeof(struct statfs *) * result;

        while(buf_ptr < buf_end) {
            if([_shadow isCPathRestricted:(*buf_ptr)->f_mntonname]) {
                // handle bindfs/chroot
                strcpy((*buf_ptr)->f_mntonname, "/");
            }

            if(strcmp((*buf_ptr)->f_mntonname, "/") == 0) {
                // Mark rootfs read-only
                (*buf_ptr)->f_flags |= MNT_RDONLY | MNT_ROOTFS | MNT_SNAPSHOT;
                break;
            }

            buf_ptr++;
        }
    }

    return result;
}

static int (*original_statfs)(const char* pathname, struct statfs* buf);
static int replaced_statfs(const char* pathname, struct statfs* buf) {
    if(isCallerTweak()) {
        return original_statfs(pathname, buf);
    }

    if([_shadow isCPathRestricted:pathname]) {
        errno = ENOENT;
        return -1;
    }

    int result = original_statfs(pathname, buf);

    if(result == 0) {
        // Modify flags
        if(buf) {
            if([_shadow isCPathRestricted:buf->f_mntonname]) {
                // handle bindfs/chroot
                strcpy(buf->f_mntonname, "/");
            }

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
    if(isCallerTweak()) {
        return original_fstatfs(fd, buf);
    }

    if(fd != fileno(stderr)
    && fd != fileno(stdout)
    && fd != fileno(stdin)) {
        // Get file descriptor path.
        char pathname[PATH_MAX];

        if(fcntl(fd, F_GETPATH, pathname) != -1 && [_shadow isCPathRestricted:pathname]) {
            errno = EBADF;
            return -1;
        }
    }

    int result = original_fstatfs(fd, buf);

    if(result == 0) {
        // Modify flags
        if(buf) {
            if([_shadow isCPathRestricted:buf->f_mntonname]) {
                // handle bindfs/chroot
                strcpy(buf->f_mntonname, "/");
            }

            if(strcmp(buf->f_mntonname, "/") == 0) {
                // Mark rootfs read-only
                buf->f_flags |= MNT_RDONLY | MNT_ROOTFS | MNT_SNAPSHOT;
            }
        }
    }

    return result;
}

static int (*original_statvfs)(const char* pathname, struct statvfs* buf);
static int replaced_statvfs(const char* pathname, struct statvfs* buf) {
    if(isCallerTweak()) {
        return original_statvfs(pathname, buf);
    }

    if([_shadow isCPathRestricted:pathname]) {
        errno = ENOENT;
        return -1;
    }

    // use statfs to get f_mntonname
    struct statfs st;
    if(statfs(pathname, &st) == -1) {
        memset(buf, 0, sizeof(struct statvfs));
        errno = ENOENT;
        return -1;
    }

    int result = original_statvfs(pathname, buf);

    if(result == 0) {
        if([_shadow isCPathRestricted:st.f_mntonname]) {
            // handle bindfs/chroot
            strcpy(st.f_mntonname, "/");
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
    if(isCallerTweak()) {
        return original_fstatvfs(fd, buf);
    }

    // use fstatfs to get f_mntonname, replaced version for path checking
    struct statfs st;
    if(replaced_fstatfs(fd, &st) == -1) {
        memset(buf, 0, sizeof(struct statvfs));
        errno = EBADF;
        return -1;
    }

    int result = original_fstatvfs(fd, buf);

    if(result == 0) {
        if([_shadow isCPathRestricted:st.f_mntonname]) {
            // handle bindfs/chroot
            strcpy(st.f_mntonname, "/");
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

    if(result != -1 && !isCallerTweak() && [_shadow isCPathRestricted:pathname]) {
        if(buf) {
            memset(buf, 0, sizeof(struct stat));
        }
        
        errno = ENOENT;
        return -1;
    }

    return result;
}

static int (*original_lstat)(const char* pathname, struct stat* buf);
static int replaced_lstat(const char* pathname, struct stat* buf) {
    if(isCallerTweak()) {
        return original_lstat(pathname, buf);
    }

    struct stat _buf;
    int result = original_lstat(pathname, &_buf);

    if(result == 0) {
        NSString* path = [NSString stringWithUTF8String:pathname];

        // Only use resolve flag if target is not a symlink.
        if([_shadow isPathRestricted:path options:@{kShadowRestrictionEnableResolve : @(!(_buf.st_mode & S_IFLNK))}]) {
            errno = ENOENT;
            return -1;
        }
    }

    if(buf) {
        memcpy(buf, &_buf, sizeof(struct stat));
    }

    return result;
}

static int (*original_fstat)(int fd, struct stat* buf);
static int replaced_fstat(int fd, struct stat* buf) {
    if(isCallerTweak()) {
        return original_fstat(fd, buf);
    }

    if(fd != fileno(stderr)
    && fd != fileno(stdout)
    && fd != fileno(stdin)) {
        // Get file descriptor path.
        char pathname[PATH_MAX];

        if(fcntl(fd, F_GETPATH, pathname) != -1 && [_shadow isCPathRestricted:pathname]) {
            errno = EBADF;
            return -1;
        }
    }

    return original_fstat(fd, buf);
}

static int (*original_fstatat)(int dirfd, const char* pathname, struct stat* buf, int flags);
static int replaced_fstatat(int dirfd, const char* pathname, struct stat* buf, int flags) {
    if(isCallerTweak()) {
        return original_fstatat(dirfd, pathname, buf, flags);
    }

    if(pathname
    && dirfd != fileno(stderr)
    && dirfd != fileno(stdout)
    && dirfd != fileno(stdin)) {
        NSString* path = [NSString stringWithUTF8String:pathname];

        // Get file descriptor path.
        char pathnameParent[PATH_MAX];
        NSString* pathParent = nil;

        if(dirfd == AT_FDCWD) {
            pathParent = [[NSFileManager defaultManager] currentDirectoryPath];
        } else if(fcntl(dirfd, F_GETPATH, pathnameParent) != -1) {
            pathParent = [NSString stringWithUTF8String:pathnameParent];
        }

        if([_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : pathParent}]) {
            errno = [path isAbsolutePath] ? ENOENT : EBADF;
            return -1;
        }
    }

    return original_fstatat(dirfd, pathname, buf, flags);
}

static int (*original_faccessat)(int dirfd, const char* pathname, int mode, int flags);
static int replaced_faccessat(int dirfd, const char* pathname, int mode, int flags) {
    if(isCallerTweak()) {
        return original_faccessat(dirfd, pathname, mode, flags);
    }

    if(pathname
    && dirfd != fileno(stderr)
    && dirfd != fileno(stdout)
    && dirfd != fileno(stdin)) {
        NSString* path = [NSString stringWithUTF8String:pathname];

        // Get file descriptor path.
        char pathnameParent[PATH_MAX];
        NSString* pathParent = nil;

        if(dirfd == AT_FDCWD) {
            pathParent = [[NSFileManager defaultManager] currentDirectoryPath];
        } else if(fcntl(dirfd, F_GETPATH, pathnameParent) != -1) {
            pathParent = [NSString stringWithUTF8String:pathnameParent];
        }

        if([_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : pathParent}]) {
            errno = [path isAbsolutePath] ? ENOENT : EBADF;
            return -1;
        }
    }

    return original_faccessat(dirfd, pathname, mode, flags);
}

// static int (*original_scandir)(const char* dirname, struct dirent*** namelist, int (*select)(struct dirent *), int (*compar)(const void *, const void *));
// static int replaced_scandir(const char* dirname, struct dirent*** namelist, int (*select)(struct dirent *), int (*compar)(const void *, const void *)) {
//     int result = original_scandir(dirname, namelist, select, compar);

//     return result;
// }

static int (*original_readdir_r)(DIR* dirp, struct dirent* entry, struct dirent** oresult);
static int replaced_readdir_r(DIR* dirp, struct dirent* entry, struct dirent** oresult) {
    if(isCallerTweak()) {
        return original_readdir_r(dirp, entry, oresult);
    }

    int result = original_readdir_r(dirp, entry, oresult);
    
    if(result == 0 && *oresult) {
        int fd = dirfd(dirp);

        // Get file descriptor path.
        char pathname[PATH_MAX];

        if(fcntl(fd, F_GETPATH, pathname) != -1) {
            NSString* pathParent = [NSString stringWithUTF8String:pathname];

            do {
                if([_shadow isPathRestricted:@((*oresult)->d_name) options:@{kShadowRestrictionWorkingDir : pathParent}]) {
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
    if(isCallerTweak()) {
        return original_readdir(dirp);
    }

    struct dirent* result = original_readdir(dirp);
    
    if(result) {
        int fd = dirfd(dirp);

        // Get file descriptor path.
        char pathname[PATH_MAX];
        
        if(fcntl(fd, F_GETPATH, pathname) != -1) {
            NSString* pathParent = [NSString stringWithUTF8String:pathname];

            do {
                if([_shadow isPathRestricted:@(result->d_name) options:@{kShadowRestrictionWorkingDir : pathParent}]) {
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
    if(isCallerTweak() || ![_shadow isCPathRestricted:pathname]) {
        return original_fopen(pathname, mode);
    }

    errno = ENOENT;
    return NULL;
}

static FILE* (*original_freopen)(const char* pathname, const char* mode, FILE* stream);
static FILE* replaced_freopen(const char* pathname, const char* mode, FILE* stream) {
    if(isCallerTweak() || ![_shadow isCPathRestricted:pathname]) {
        return original_freopen(pathname, mode, stream);
    }

    errno = ENOENT;
    return NULL;
}

static char* (*original_realpath)(const char* pathname, char* resolved_path);
static char* replaced_realpath(const char* pathname, char* resolved_path) {
    char* result = original_realpath(pathname, resolved_path);

    if(result && !isCallerTweak() && [_shadow isCPathRestricted:pathname]) {
        errno = ENOENT;
        return NULL;
    }

    return result;
}

static int (*original_getattrlist)(const char* path, struct attrlist* attrList, void* attrBuf, size_t attrBufSize, unsigned long options);
static int replaced_getattrlist(const char* path, struct attrlist* attrList, void* attrBuf, size_t attrBufSize, unsigned long options) {
    int result = original_getattrlist(path, attrList, attrBuf, attrBufSize, options);

    if(result != -1 && !isCallerTweak() && [_shadow isCPathRestricted:path]) {
        errno = ENOENT;
        return -1;
    }

    return result;
}

static int (*original_symlink)(const char* path1, const char* path2);
static int replaced_symlink(const char* path1, const char* path2) {
    if(isCallerTweak() || ![_shadow isCPathRestricted:path2]) {
        return original_symlink(path1, path2);
    }

    errno = EACCES;
    return -1;
}

static int (*original_link)(const char* path1, const char* path2);
static int replaced_link(const char* path1, const char* path2) {
    if(isCallerTweak() || !([_shadow isCPathRestricted:path1] || [_shadow isCPathRestricted:path2])) {
        return original_link(path1, path2);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_rename)(const char* old, const char* new);
static int replaced_rename(const char* old, const char* new) {
    if(isCallerTweak() || !([_shadow isCPathRestricted:old] || [_shadow isCPathRestricted:new])) {
        return original_rename(old, new);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_remove)(const char* pathname);
static int replaced_remove(const char* pathname) {
    if(isCallerTweak() || ![_shadow isCPathRestricted:pathname]) {
        return original_remove(pathname);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_unlink)(const char* pathname);
static int replaced_unlink(const char* pathname) {
    if(isCallerTweak() || ![_shadow isCPathRestricted:pathname]) {
        return original_unlink(pathname);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_unlinkat)(int dirfd, const char* pathname, int flags);
static int replaced_unlinkat(int dirfd, const char* pathname, int flags) {
    if(isCallerTweak()) {
        return original_unlinkat(dirfd, pathname, flags);
    }

    if(pathname
    && dirfd != fileno(stderr)
    && dirfd != fileno(stdout)
    && dirfd != fileno(stdin)) {
        NSString* path = [NSString stringWithUTF8String:pathname];

        // Get file descriptor path.
        char pathnameParent[PATH_MAX];
        NSString* pathParent = nil;

        if(dirfd == AT_FDCWD) {
            pathParent = [[NSFileManager defaultManager] currentDirectoryPath];
        } else if(fcntl(dirfd, F_GETPATH, pathnameParent) != -1) {
            pathParent = [NSString stringWithUTF8String:pathnameParent];
        }

        if([_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : pathParent}]) {
            errno = [path isAbsolutePath] ? ENOENT : EBADF;
            return -1;
        }
    }

    return original_unlinkat(dirfd, pathname, flags);
}

static int (*original_rmdir)(const char* pathname);
static int replaced_rmdir(const char* pathname) {
    if(isCallerTweak() || ![_shadow isCPathRestricted:pathname]) {
        return original_rmdir(pathname);
    }

    errno = ENOENT;
    return -1;
}

static long (*original_pathconf)(const char* pathname, int name);
static long replaced_pathconf(const char* pathname, int name) {
    if(isCallerTweak() || ![_shadow isCPathRestricted:pathname]) {
        return original_pathconf(pathname, name);
    }

    errno = ENOENT;
    return -1;
}

static long (*original_fpathconf)(int fd, int name);
static long replaced_fpathconf(int fd, int name) {
    if(isCallerTweak()) {
        return original_fpathconf(fd, name);
    }
    
    if(fd != fileno(stderr)
    && fd != fileno(stdout)
    && fd != fileno(stdin)) {
        // Get file descriptor path.
        char pathname[PATH_MAX];

        if(fcntl(fd, F_GETPATH, pathname) != -1 && [_shadow isCPathRestricted:pathname]) {
            errno = EBADF;
            return -1;
        }
    }

    return original_fpathconf(fd, name);
}

static int (*original_utimes)(const char* pathname, const struct timeval times[2]);
static int replaced_utimes(const char* pathname, const struct timeval times[2]) {
    if(isCallerTweak() || ![_shadow isCPathRestricted:pathname]) {
        return original_utimes(pathname, times);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_futimes)(int fd, const struct timeval times[2]);
static int replaced_futimes(int fd, const struct timeval times[2]) {
    if(isCallerTweak()) {
        return original_futimes(fd, times);
    }
    
    if(fd != fileno(stderr)
    && fd != fileno(stdout)
    && fd != fileno(stdin)) {
        // Get file descriptor path.
        char pathname[PATH_MAX];

        if(fcntl(fd, F_GETPATH, pathname) != -1 && [_shadow isCPathRestricted:pathname]) {
            errno = EBADF;
            return -1;
        }
    }

    return original_futimes(fd, times);
}

static char* (*original_getenv)(const char* name);
static char* replaced_getenv(const char* name) {
    if(isCallerTweak()) {
        return original_getenv(name);
    }

    char* result = original_getenv(name);

    // if(result && name) {
    //     if(strcmp(name, "DYLD_INSERT_LIBRARIES") == 0
    //     || strcmp(name, "_MSSafeMode") == 0
    //     || strcmp(name, "_SafeMode") == 0
    //     || strcmp(name, "_SubstituteSafeMode") == 0) {
    //         return NULL;
    //     }

    //     if(strcmp(name, "SHELL") == 0) {
    //         return "/bin/sh";
    //     }
    // }

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

            if(p->kp_proc.p_flag & P_TRACED) {
                p->kp_proc.p_flag &= ~P_TRACED;
            }

            if(p->kp_proc.p_flag & P_SELECT) {
                p->kp_proc.p_flag &= ~P_SELECT;
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

    if(isCallerTweak() || ![_shadow isCPathRestricted:pathname]) {
        return original_open(pathname, oflag, arg);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_openat)(int dirfd, const char *pathname, int oflag, ...);
static int replaced_openat(int dirfd, const char *pathname, int oflag, ...) {
    void* arg;
    va_list args;
    va_start(args, oflag);
    arg = va_arg(args, void *);
    va_end(args);

    if(isCallerTweak()) {
        return original_openat(dirfd, pathname, oflag, arg);
    }

    if(pathname
    && dirfd != fileno(stderr)
    && dirfd != fileno(stdout)
    && dirfd != fileno(stdin)) {
        NSString* path = [NSString stringWithUTF8String:pathname];

        // Get file descriptor path.
        char pathnameParent[PATH_MAX];
        NSString* pathParent = nil;

        if(dirfd == AT_FDCWD) {
            pathParent = [[NSFileManager defaultManager] currentDirectoryPath];
        } else if(fcntl(dirfd, F_GETPATH, pathnameParent) != -1) {
            pathParent = [NSString stringWithUTF8String:pathnameParent];
        }

        if([_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : pathParent}]) {
            errno = [path isAbsolutePath] ? ENOENT : EBADF;
            return -1;
        }
    }

    return original_openat(dirfd, pathname, oflag, arg);
}

static DIR* (*original___opendir2)(const char* pathname, size_t bufsize);
static DIR* replaced___opendir2(const char* pathname, size_t bufsize) {
    if(isCallerTweak() || ![_shadow isCPathRestricted:pathname]) {
        return original___opendir2(pathname, bufsize);
    }

    errno = ENOENT;
    return NULL;
}

void shadowhook_libc(HKSubstitutor* hooks) {
    MSHookFunction(access, replaced_access, (void **) &original_access);
    MSHookFunction(chdir, replaced_chdir, (void **) &original_chdir);
    MSHookFunction(chroot, replaced_chroot, (void **) &original_chroot);
    MSHookFunction(creat, replaced_creat, (void **) &original_creat);
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
    MSHookFunction(getmntinfo, replaced_getmntinfo, (void **) &original_getmntinfo);
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
    MSHookFunction(fstat, replaced_fstat, (void **) &original_fstat);
    MSHookFunction(fstatat, replaced_fstatat, (void **) &original_fstatat);
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
}
