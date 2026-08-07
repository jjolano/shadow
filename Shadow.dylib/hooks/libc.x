#import "hooks.h"

#import <string.h>
#import <stdlib.h>
#import <os/lock.h>

// Behavioral tripwire: any non-tweak caller touching a jailbreak-indicator
// path is a detector, whatever it calls itself — renamed, obfuscated, or
// statically linked into the app binary (which has no image name at all for
// the watcher's name scan to see). High-signal set: stock devices never have
// these paths and app code never touches them except to probe.
static BOOL shdw_is_jb_probe(const char* path) {
    if(!path || !path[0]) {
        return NO;
    }

    return strstr(path, "/var/jb") != NULL
        || strstr(path, "/var/binpack") != NULL
        || strstr(path, "/jbroot") != NULL
        || strstr(path, "/.installed_") != NULL
        || strstr(path, "/.bootstrapped_") != NULL
        || strstr(path, "/var/lib/dpkg") != NULL
        || strstr(path, "/var/lib/apt") != NULL
        || strstr(path, "/usr/lib/libhooker.dylib") != NULL
        || strstr(path, "/usr/lib/libsubstrate.dylib") != NULL
        || strstr(path, "/usr/lib/libsubstitute") != NULL
        || strstr(path, "/usr/lib/libellekit.dylib") != NULL
        || strstr(path, "/usr/lib/pspawn_payload") != NULL
        || strstr(path, "/usr/lib/tweakloader.dylib") != NULL
        || strstr(path, "/usr/lib/libjailbreak.dylib") != NULL
        || strstr(path, "MobileSubstrate.dylib") != NULL;
}

// Trip on the attempt, before any restricted-path filtering: the probe is the
// caller touching a JB indicator, independent of how the filter answers it.
// isCallerExternal() reads the return address, so it must expand inline at the
// hook site — never route it through a helper function.
#define SHADOW_TRIP(pathname, kind) \
    if(!isCallerExternal() && shdw_is_jb_probe(pathname)) { \
        shdw_detector_detected(kind); \
    }

static int (*original_access)(const char* pathname, int mode);
static int replaced_access(const char* pathname, int mode) {
    SHADOW_TRIP(pathname, "access");

    int result = original_access(pathname, mode);

    if(result != -1 && !isCallerExternal() && [_shadow isCPathRestricted:pathname]) {
        errno = ENOENT;
        return -1;
    }

    return result;
}

static ssize_t (*original_readlink)(const char* pathname, char* buf, size_t bufsize);
static ssize_t replaced_readlink(const char* pathname, char* buf, size_t bufsize) {
    if(isCallerExternal()) {
        return original_readlink(pathname, buf, bufsize);
    }

    NSString* path = [NSString stringWithUTF8String:pathname];

    // NoFollow: this is a link-LOCATION check — Core's resolve-before-exempt
    // must not realpath through the link, which would evaluate its target
    // instead of the link path itself.
    if([_shadow isPathRestricted:path options:@{kShadowRestrictionNoFollow : @YES}]) {
        errno = ENOENT;
        return -1;
    }

    // buf NULL or bufsize 0: stock readlink fails (EFAULT/EINVAL); the
    // local-buffer path below must not turn those into a success.
    if(buf == NULL || bufsize == 0) {
        return original_readlink(pathname, buf, bufsize);
    }

    // Read into a temp buffer first: a link stored in a safe location can
    // still name a restricted path in its CONTENT, and on denial the
    // caller's buffer must be left untouched.
    char content[PATH_MAX];
    ssize_t result = original_readlink(pathname, content, sizeof(content));

    if(result != -1 && result < (ssize_t) sizeof(content)) {
        content[result] = '\0';

        if([_shadow isCPathRestricted:content]) {
            errno = EACCES;
            return -1;
        }

        size_t copy_len = (size_t) result;

        if(copy_len > bufsize) {
            copy_len = bufsize;
        }

        if(buf && copy_len > 0) {
            memcpy(buf, content, copy_len);
        }

        return (ssize_t) copy_len;
    }

    // ponytail: a link longer than PATH_MAX can't be validated as a string;
    // it can't be a JB indicator path either (those are short), so forward.
    return result;
}

static ssize_t (*original_readlinkat)(int dirfd, const char* pathname, char* buf, size_t bufsize);
static ssize_t replaced_readlinkat(int dirfd, const char* pathname, char* buf, size_t bufsize) {
    if(isCallerExternal()) {
        return original_readlinkat(dirfd, pathname, buf, bufsize);
    }

    if(pathname
    && dirfd != fileno(stderr)
    && dirfd != fileno(stdout)
    && dirfd != fileno(stdin)) {
        if(pathname[0] == '/') {
            if([_shadow isCPathRestricted:pathname]) {
                errno = ENOENT;
                return -1;
            }
        } else {
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
                errno = EBADF;
                return -1;
            }
        }
    }

    return original_readlinkat(dirfd, pathname, buf, bufsize);
}

static int (*original_chdir)(const char* pathname);
static int replaced_chdir(const char* pathname) {
    if(isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_chdir(pathname);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_fchdir)(int fd);
static int replaced_fchdir(int fd) {
    if(isCallerExternal()) {
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
    if(isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_chroot(pathname);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_creat)(const char* pathname, mode_t mode);
static int replaced_creat(const char* pathname, mode_t mode) {
    if(isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_creat(pathname, mode);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_getfsstat)(struct statfs* buf, int bufsize, int flags);
static int replaced_getfsstat(struct statfs* buf, int bufsize, int flags) {
    if(isCallerExternal()) {
        return original_getfsstat(buf, bufsize, flags);
    }

    int result = original_getfsstat(buf, bufsize, flags);

    if(result > 0 && buf) {
        // getfsstat returns the TOTAL entry count; when the caller's buffer
        // is too small only bufsize/sizeof(struct statfs) entries were
        // actually written, so walking buf + result would run past the end
        // of the caller's buffer.
        int count = result;
        int capacity = bufsize / (int) sizeof(struct statfs);

        if(capacity < count) {
            count = capacity;
        }

        struct statfs* buf_ptr = buf;
        struct statfs* buf_end = buf + count;

        while(buf_ptr < buf_end) {
            if([_shadow isCPathRestricted:buf_ptr->f_mntonname]) {
                // handle bindfs/chroot
                strcpy(buf_ptr->f_mntonname, "/");
            }

            if(strcmp(buf_ptr->f_mntonname, "/") == 0) {
                // Mark rootfs read-only
                buf_ptr->f_flags |= MNT_RDONLY | MNT_ROOTFS | MNT_SNAPSHOT;
            }

            buf_ptr++;
        }
    }

    return result;
}

static int (*original_getmntinfo)(struct statfs** mntbufp, int flags);
static int replaced_getmntinfo(struct statfs** mntbufp, int flags) {
    if(isCallerExternal()) {
        return original_getmntinfo(mntbufp, flags);
    }

    int result = original_getmntinfo(mntbufp, flags);

    if(result <= 0 || *mntbufp == NULL) {
        return result;
    }

    // *mntbufp points at libc's static mount table: never mutate it in
    // place — the mangled entries would leak to the next caller of libc's
    // static getmntinfo. Copy, mutate the copy, and hand the caller the
    // new buffer (callers that free() the result free our malloc block;
    // callers that don't leak one buffer per call, same as getmntinfo_r).
    size_t bytes = (size_t) result * sizeof(struct statfs);
    struct statfs* copy = (struct statfs *) malloc(bytes);

    if(copy == NULL) {
        return result;
    }

    memcpy(copy, *mntbufp, bytes);

    struct statfs* buf_ptr = copy;
    struct statfs* buf_end = copy + result;

    while(buf_ptr < buf_end) {
        if([_shadow isCPathRestricted:buf_ptr->f_mntonname]) {
            // handle bindfs/chroot
            strcpy(buf_ptr->f_mntonname, "/");
        }

        if(strcmp(buf_ptr->f_mntonname, "/") == 0) {
            // Mark rootfs read-only
            buf_ptr->f_flags |= MNT_RDONLY | MNT_ROOTFS | MNT_SNAPSHOT;
        }

        buf_ptr++;
    }

    *mntbufp = copy;

    return result;
}

static int (*original_statfs)(const char* pathname, struct statfs* buf);
static int replaced_statfs(const char* pathname, struct statfs* buf) {
    if(isCallerExternal()) {
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
    if(isCallerExternal()) {
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
    if(isCallerExternal()) {
        return original_statvfs(pathname, buf);
    }

    if([_shadow isCPathRestricted:pathname]) {
        errno = ENOENT;
        return -1;
    }

    // use statfs to get f_mntonname; original version so the path/mount
    // restriction checks run once here instead of via the hooked statfs
    struct statfs st;
    if(original_statfs(pathname, &st) == -1) {
        // Failure path: return -1 without touching the output buffer or
        // clobbering errno (the failed original already set it).
        return -1;
    }

    int result = original_statvfs(pathname, buf);

    if(result == 0 && buf) {
        if([_shadow isCPathRestricted:st.f_mntonname]) {
            // handle bindfs/chroot
            strcpy(st.f_mntonname, "/");
        }
        
        if(strcmp(st.f_mntonname, "/") == 0) {
            // Mark rootfs read-only. statvfs.f_flag only supports the ST_*
            // constants (ST_RDONLY/ST_NOSUID); the MNT_* bits belong to
            // struct statfs and must not be OR'd in here.
            buf->f_flag |= ST_RDONLY;
        }
    }

    return result;
}

static int (*original_fstatvfs)(int fd, struct statvfs* buf);
static int replaced_fstatvfs(int fd, struct statvfs* buf) {
    if(isCallerExternal()) {
        return original_fstatvfs(fd, buf);
    }

    // use fstatfs to get f_mntonname; original version so the fd/mount
    // restriction checks run once here instead of via the hooked fstatfs
    struct statfs st;

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

    if(original_fstatfs(fd, &st) == -1) {
        // Failure path: return -1 without touching the output buffer or
        // clobbering errno (the failed original already set it).
        return -1;
    }

    int result = original_fstatvfs(fd, buf);

    if(result == 0 && buf) {
        if([_shadow isCPathRestricted:st.f_mntonname]) {
            // handle bindfs/chroot
            strcpy(st.f_mntonname, "/");
        }

        if(strcmp(st.f_mntonname, "/") == 0) {
            // Mark rootfs read-only (statvfs carries the flags in f_flag,
            // which only supports the ST_* constants, not MNT_*).
            buf->f_flag |= ST_RDONLY;
        }
    }

    return result;
}

static int (*original_stat)(const char* pathname, struct stat* buf);
static int replaced_stat(const char* pathname, struct stat* buf) {
    SHADOW_TRIP(pathname, "stat");

    int result = original_stat(pathname, buf);

    if(result != -1 && !isCallerExternal() && [_shadow isCPathRestricted:pathname]) {
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
    SHADOW_TRIP(pathname, "lstat");

    if(isCallerExternal()) {
        return original_lstat(pathname, buf);
    }

    struct stat _buf;
    int result = original_lstat(pathname, &_buf);

    if(result == 0) {
        NSString* path = [NSString stringWithUTF8String:pathname];

        // Only use resolve flag if target is not a symlink. NoFollow keeps
        // Core's resolve-before-exempt from realpath-ing through the link:
        // this is a link-LOCATION check, not a target check.
        if([_shadow isPathRestricted:path options:@{
            kShadowRestrictionEnableResolve : @(!S_ISLNK(_buf.st_mode)),
            kShadowRestrictionNoFollow : @YES
        }]) {
            errno = ENOENT;
            return -1;
        }

        // A NULL caller buffer must keep stock semantics: lstat(path, NULL)
        // fails with EFAULT. The local-buffer read above would otherwise
        // turn it into a success, so replay the NULL through the original
        // (only reached for non-restricted paths — restricted ones already
        // returned ENOENT above).
        if(buf == NULL) {
            return original_lstat(pathname, NULL);
        }

        // Only copy on success: on failure _buf is uninitialized stack.
        memcpy(buf, &_buf, sizeof(struct stat));
    }

    return result;
}

static int (*original_fstat)(int fd, struct stat* buf);
static int replaced_fstat(int fd, struct stat* buf) {
    if(isCallerExternal()) {
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
    SHADOW_TRIP(pathname, "fstatat");

    if(isCallerExternal()) {
        return original_fstatat(dirfd, pathname, buf, flags);
    }

    if(pathname
    && dirfd != fileno(stderr)
    && dirfd != fileno(stdout)
    && dirfd != fileno(stdin)) {
        if(pathname[0] == '/') {
            if([_shadow isCPathRestricted:pathname]) {
                errno = ENOENT;
                return -1;
            }
        } else {
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
                errno = EBADF;
                return -1;
            }
        }
    }

    return original_fstatat(dirfd, pathname, buf, flags);
}

static int (*original_faccessat)(int dirfd, const char* pathname, int mode, int flags);
static int replaced_faccessat(int dirfd, const char* pathname, int mode, int flags) {
    SHADOW_TRIP(pathname, "faccessat");

    if(isCallerExternal()) {
        return original_faccessat(dirfd, pathname, mode, flags);
    }

    if(pathname
    && dirfd != fileno(stderr)
    && dirfd != fileno(stdout)
    && dirfd != fileno(stdin)) {
        if(pathname[0] == '/') {
            if([_shadow isCPathRestricted:pathname]) {
                errno = ENOENT;
                return -1;
            }
        } else {
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
                errno = EBADF;
                return -1;
            }
        }
    }

    return original_faccessat(dirfd, pathname, mode, flags);
}

// static int (*original_scandir)(const char* dirname, struct dirent*** namelist, int (*select)(struct dirent *), int (*compar)(const void *, const void *));
// static int replaced_scandir(const char* dirname, struct dirent*** namelist, int (*select)(struct dirent *), int (*compar)(const void *, const void *)) {
//     int result = original_scandir(dirname, namelist, select, compar);

//     return result;
// }

// readdir/readdir_r used to resolve the DIR*'s parent path (dirfd + F_GETPATH)
// and build the options dictionary for every entry. Cache both per DIR* so
// only the per-entry child check runs; invalidated on closedir because DIR*
// pointers get reused. Fixed-size table, round-robin eviction on overflow
// (a miss just re-resolves — results stay identical). F_GETPATH failure is
// cached too: the original code then skips filtering entirely.
#define SHADW_READDIR_CACHE_SIZE 16

static struct {
    DIR* dirp;
    CFDictionaryRef options; // retained; NULL when F_GETPATH failed (no filtering)
} shdw_readdir_cache[SHADW_READDIR_CACHE_SIZE];

static NSUInteger shdw_readdir_cache_next = 0;
static os_unfair_lock shdw_readdir_cache_lock = OS_UNFAIR_LOCK_INIT;

static void shdw_readdir_cache_clear_locked(DIR* dirp) {
    for(NSUInteger i = 0; i < SHADW_READDIR_CACHE_SIZE; i++) {
        if(shdw_readdir_cache[i].dirp == dirp) {
            if(shdw_readdir_cache[i].options) {
                CFRelease(shdw_readdir_cache[i].options);
            }

            shdw_readdir_cache[i].dirp = NULL;
            shdw_readdir_cache[i].options = NULL;
            break;
        }
    }
}

// Returns a retained options dict for the DIR*'s parent path (caller must
// CFRelease), or NULL when no filtering applies / the parent can't be resolved.
static NSDictionary* shdw_readdir_cache_options(DIR* dirp) {
    os_unfair_lock_lock(&shdw_readdir_cache_lock);

    NSDictionary* result = nil;
    BOOL cached = NO;

    for(NSUInteger i = 0; i < SHADW_READDIR_CACHE_SIZE; i++) {
        if(shdw_readdir_cache[i].dirp == dirp) {
            cached = YES;

            if(shdw_readdir_cache[i].options) {
                result = (__bridge NSDictionary*)CFRetain(shdw_readdir_cache[i].options);
            }

            break;
        }
    }

    if(!cached) {
        char pathname[PATH_MAX];
        NSDictionary* options = nil;

        if(fcntl(dirfd(dirp), F_GETPATH, pathname) != -1) {
            options = @{kShadowRestrictionWorkingDir : [NSString stringWithUTF8String:pathname]};
            result = (__bridge NSDictionary*)CFRetain((__bridge CFDictionaryRef)options);
        }

        // Evict the next slot (may drop a live DIR*'s entry; a miss just re-resolves).
        NSUInteger slot = shdw_readdir_cache_next;
        shdw_readdir_cache_next = (shdw_readdir_cache_next + 1) % SHADW_READDIR_CACHE_SIZE;

        if(shdw_readdir_cache[slot].options) {
            CFRelease(shdw_readdir_cache[slot].options);
        }

        shdw_readdir_cache[slot].dirp = dirp;
        shdw_readdir_cache[slot].options = options ? CFRetain((__bridge CFDictionaryRef)options) : NULL;
    }

    os_unfair_lock_unlock(&shdw_readdir_cache_lock);
    return result;
}

static int (*original_readdir_r)(DIR* dirp, struct dirent* entry, struct dirent** oresult);
static int replaced_readdir_r(DIR* dirp, struct dirent* entry, struct dirent** oresult) {
    if(isCallerExternal()) {
        return original_readdir_r(dirp, entry, oresult);
    }

    int result = original_readdir_r(dirp, entry, oresult);
    
    if(result == 0 && *oresult) {
        NSDictionary* options = shdw_readdir_cache_options(dirp);

        if(options) {
            do {
                if([_shadow isPathRestricted:@((*oresult)->d_name) options:options]) {
                    // call readdir again to skip ahead
                    result = original_readdir_r(dirp, entry, oresult);
                } else {
                    break;
                }
            } while(result == 0 && *oresult);

            CFRelease((__bridge CFDictionaryRef)options);
        }
    }

    return result;
}

static struct dirent* (*original_readdir)(DIR* dirp);
static struct dirent* replaced_readdir(DIR* dirp) {
    if(isCallerExternal()) {
        return original_readdir(dirp);
    }

    struct dirent* result = original_readdir(dirp);
    
    if(result) {
        NSDictionary* options = shdw_readdir_cache_options(dirp);

        if(options) {
            do {
                if([_shadow isPathRestricted:@(result->d_name) options:options]) {
                    // call readdir again to skip ahead
                    result = original_readdir(dirp);
                } else {
                    break;
                }
            } while(result);

            CFRelease((__bridge CFDictionaryRef)options);
        }
    }

    return result;
}

static int (*original_closedir)(DIR* dirp);
static int replaced_closedir(DIR* dirp) {
    os_unfair_lock_lock(&shdw_readdir_cache_lock);
    shdw_readdir_cache_clear_locked(dirp);
    os_unfair_lock_unlock(&shdw_readdir_cache_lock);

    return original_closedir(dirp);
}

static FILE* (*original_fopen)(const char* pathname, const char* mode);
static FILE* replaced_fopen(const char* pathname, const char* mode) {
    SHADOW_TRIP(pathname, "fopen");

    if(isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_fopen(pathname, mode);
    }

    errno = ENOENT;
    return NULL;
}

static FILE* (*original_freopen)(const char* pathname, const char* mode, FILE* stream);
static FILE* replaced_freopen(const char* pathname, const char* mode, FILE* stream) {
    if(isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_freopen(pathname, mode, stream);
    }

    errno = ENOENT;
    return NULL;
}

static char* (*original_realpath)(const char* pathname, char* resolved_path);
static char* replaced_realpath(const char* pathname, char* resolved_path) {
    char* result = original_realpath(pathname, resolved_path);

    if(result && !isCallerExternal()) {
        if([_shadow isCPathRestricted:pathname]) {
            errno = ENOENT;
            return NULL;
        }

        // The returned path is the fully resolved TARGET: a symlink chain
        // can land in a restricted location even when the input path is
        // not restricted, so check the resolved string as well.
        if([_shadow isCPathRestricted:result]) {
            errno = EACCES;
            return NULL;
        }
    }

    return result;
}

static int (*original_getattrlist)(const char* path, struct attrlist* attrList, void* attrBuf, size_t attrBufSize, unsigned long options);
static int replaced_getattrlist(const char* path, struct attrlist* attrList, void* attrBuf, size_t attrBufSize, unsigned long options) {
    SHADOW_TRIP(path, "getattrlist");

    int result = original_getattrlist(path, attrList, attrBuf, attrBufSize, options);

    if(result != -1 && !isCallerExternal() && [_shadow isCPathRestricted:path]) {
        errno = ENOENT;
        return -1;
    }

    return result;
}

static int (*original_symlink)(const char* path1, const char* path2);
static int replaced_symlink(const char* path1, const char* path2) {
    if(isCallerExternal()) {
        return original_symlink(path1, path2);
    }

    // Check both the link location (path2) and the link TARGET (path1):
    // detection code can create a symlink pointing at a restricted path.
    if([_shadow isCPathRestricted:path1] || [_shadow isCPathRestricted:path2]) {
        errno = EACCES;
        return -1;
    }

    // A RELATIVE target is interpreted by the filesystem relative to the
    // directory CONTAINING THE LINK, so the joined path is what actually
    // resolves when the link is used — check that instead of the raw
    // relative string (which the restriction check can't judge).
    if(path1 && path1[0] != '/') {
        NSString* target = [NSString stringWithUTF8String:path1];
        NSString* linkDir = path2 ? [[NSString stringWithUTF8String:path2] stringByDeletingLastPathComponent] : nil;

        if(!linkDir || linkDir.length == 0 || [linkDir isEqualToString:@"."]) {
            linkDir = [[NSFileManager defaultManager] currentDirectoryPath];
        } else if(![linkDir hasPrefix:@"/"]) {
            linkDir = [[[NSFileManager defaultManager] currentDirectoryPath] stringByAppendingPathComponent:linkDir];
        }

        NSString* joined = [[linkDir stringByAppendingPathComponent:target] stringByStandardizingPath];

        if([_shadow isCPathRestricted:[joined fileSystemRepresentation]]) {
            errno = EACCES;
            return -1;
        }
    }

    return original_symlink(path1, path2);
}

static int (*original_link)(const char* path1, const char* path2);
static int replaced_link(const char* path1, const char* path2) {
    if(isCallerExternal() || !([_shadow isCPathRestricted:path1] || [_shadow isCPathRestricted:path2])) {
        return original_link(path1, path2);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_rename)(const char* old, const char* new);
static int replaced_rename(const char* old, const char* new) {
    if(isCallerExternal() || !([_shadow isCPathRestricted:old] || [_shadow isCPathRestricted:new])) {
        return original_rename(old, new);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_remove)(const char* pathname);
static int replaced_remove(const char* pathname) {
    if(isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_remove(pathname);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_unlink)(const char* pathname);
static int replaced_unlink(const char* pathname) {
    if(isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_unlink(pathname);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_unlinkat)(int dirfd, const char* pathname, int flags);
static int replaced_unlinkat(int dirfd, const char* pathname, int flags) {
    if(isCallerExternal()) {
        return original_unlinkat(dirfd, pathname, flags);
    }

    if(pathname
    && dirfd != fileno(stderr)
    && dirfd != fileno(stdout)
    && dirfd != fileno(stdin)) {
        if(pathname[0] == '/') {
            if([_shadow isCPathRestricted:pathname]) {
                errno = ENOENT;
                return -1;
            }
        } else {
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
                errno = EBADF;
                return -1;
            }
        }
    }

    return original_unlinkat(dirfd, pathname, flags);
}

static int (*original_rmdir)(const char* pathname);
static int replaced_rmdir(const char* pathname) {
    if(isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_rmdir(pathname);
    }

    errno = ENOENT;
    return -1;
}

static long (*original_pathconf)(const char* pathname, int name);
static long replaced_pathconf(const char* pathname, int name) {
    if(isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_pathconf(pathname, name);
    }

    errno = ENOENT;
    return -1;
}

static long (*original_fpathconf)(int fd, int name);
static long replaced_fpathconf(int fd, int name) {
    if(isCallerExternal()) {
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
    if(isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_utimes(pathname, times);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_futimes)(int fd, const struct timeval times[2]);
static int replaced_futimes(int fd, const struct timeval times[2]) {
    if(isCallerExternal()) {
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
    if(isCallerExternal()) {
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

// freeRASP rootless probe: writing under @executable_path/.jbroot succeeds on
// jailbroken devices (symlink into writable bootstrap) and fails on stock.
// Fail the same way stock does (ENOENT — the path doesn't resolve).
static BOOL shdw_is_jbroot_write_probe(const char* pathname, int oflag) {
    return pathname
        && (oflag & O_CREAT)
        && (strstr(pathname, ".jbroot") != NULL);
}

static int (*original_open)(const char *pathname, int oflag, ...);
static int replaced_open(const char *pathname, int oflag, ...) {
    SHADOW_TRIP(pathname, "open");

    mode_t mode = 0;

    // open() only receives a mode argument when O_CREAT is set; reading the
    // vararg unconditionally would pull a non-existent argument off the
    // stack (the mode slot holds garbage the caller never passed).
    if(oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        // mode_t is unsigned short: through `...` it promotes to int, so read
        // the promoted slot (va_arg on the un-promoted type is UB per clang).
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }

    if(!isCallerExternal() && shdw_is_jbroot_write_probe(pathname, oflag)) {
        // Stock fails with ENOENT since .jbroot doesn't exist there; must match
        // exactly so the probe can't distinguish us via a different errno.
        errno = ENOENT;
        return -1;
    }

    if(isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        if(oflag & O_CREAT) {
            return original_open(pathname, oflag, mode);
        }

        return original_open(pathname, oflag);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_openat)(int dirfd, const char *pathname, int oflag, ...);
static int replaced_openat(int dirfd, const char *pathname, int oflag, ...) {
    SHADOW_TRIP(pathname, "openat");

    mode_t mode = 0;

    // openat() only receives a mode argument when O_CREAT is set (see open).
    if(oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        // mode_t is unsigned short: through `...` it promotes to int, so read
        // the promoted slot (va_arg on the un-promoted type is UB per clang).
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }

    if(isCallerExternal()) {
        if(oflag & O_CREAT) {
            return original_openat(dirfd, pathname, oflag, mode);
        }

        return original_openat(dirfd, pathname, oflag);
    }

    if(shdw_is_jbroot_write_probe(pathname, oflag)) {
        // Stock fails with ENOENT since .jbroot doesn't exist there; must match
        // exactly so the probe can't distinguish us via a different errno.
        errno = ENOENT;
        return -1;
    }

    if(pathname
    && dirfd != fileno(stderr)
    && dirfd != fileno(stdout)
    && dirfd != fileno(stdin)) {
        if(pathname[0] == '/') {
            if([_shadow isCPathRestricted:pathname]) {
                errno = ENOENT;
                return -1;
            }
        } else {
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
                errno = EBADF;
                return -1;
            }
        }
    }

    if(oflag & O_CREAT) {
        return original_openat(dirfd, pathname, oflag, mode);
    }

    return original_openat(dirfd, pathname, oflag);
}

static DIR* (*original___opendir2)(const char* pathname, int flags);
static DIR* replaced___opendir2(const char* pathname, int flags) {
    if(isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original___opendir2(pathname, flags);
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
    MSHookFunction(closedir, replaced_closedir, (void **) &original_closedir);
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
