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

// Shared dirfd→path resolution for the *at family. Classifies a dirfd+path
// pair without trusting the fd NUMBER: descriptors 0-2 can be closed and
// reused, so a hook that exempts them filters by identity, not number.
// Absolute paths ignore dirfd entirely; relative paths resolve against
// AT_FDCWD (process cwd) or the dirfd's own path via F_GETPATH. The caller
// replays the original call for descriptors it must not judge (the kernel
// reports the genuine EBADF/ENOTDIR), and fails closed with ENOENT for a
// valid directory vnode whose path cannot be resolved — EBADF on a valid
// dirfd is a fingerprint, ENOENT is what a stock device answers for a path
// query that must not succeed.
typedef enum {
    SHADW_DIRFD_OK = 0,        // `out` holds the resolved parent directory
    SHADW_DIRFD_ABSOLUTE,      // path is absolute; dirfd is irrelevant
    SHADW_DIRFD_ORIGINAL,      // replay the original call (kernel reports the genuine error)
    SHADW_DIRFD_DENY,          // valid dir vnode, path unresolvable: fail closed
} shdw_dirfd_status_t;

static shdw_dirfd_status_t shdw_resolve_dirfd_path(int dirfd, const char* path, char* out, size_t outlen) {
    if(path == NULL || path[0] == '\0') {
        // No path semantics to classify here — EFAULT/EINVAL come from the kernel.
        return SHADW_DIRFD_ORIGINAL;
    }

    if(path[0] == '/') {
        return SHADW_DIRFD_ABSOLUTE;
    }

    if(dirfd == AT_FDCWD) {
        return getcwd(out, outlen) ? SHADW_DIRFD_OK : SHADW_DIRFD_DENY;
    }

    if(fcntl(dirfd, F_GETPATH, out) != -1) {
        return SHADW_DIRFD_OK;
    }

    struct stat st;

    if(fstat(dirfd, &st) == 0 && S_ISDIR(st.st_mode)) {
        // Valid directory vnode that can't be named: fail closed.
        return SHADW_DIRFD_DENY;
    }

    // Invalid or non-directory descriptor: the kernel reports the genuine
    // error (EBADF/ENOTDIR) — never synthesize one here.
    return SHADW_DIRFD_ORIGINAL;
}

// Applies the shared dirfd resolution to one *at path argument: returns YES
// when the query must be denied (errno = ENOENT already set). Each hook gates
// on isCallerExternal() first, keeping the return-address read inline at the
// hook site — this helper is never reached for tweak/system callers.
static BOOL shdw_at_path_denied(int dirfd, const char* pathname) {
    if(pathname == NULL || pathname[0] == '\0') {
        return NO;
    }

    char parent[PATH_MAX];
    shdw_dirfd_status_t status = shdw_resolve_dirfd_path(dirfd, pathname, parent, sizeof(parent));

    if(status == SHADW_DIRFD_ABSOLUTE) {
        if([_shadow isCPathRestricted:pathname]) {
            errno = ENOENT;
            return YES;
        }
    } else if(status == SHADW_DIRFD_DENY) {
        errno = ENOENT;
        return YES;
    } else if(status == SHADW_DIRFD_OK) {
        NSString* path = [NSString stringWithUTF8String:pathname];

        if([_shadow isPathRestricted:path options:@{kShadowRestrictionWorkingDir : [NSString stringWithUTF8String:parent]}]) {
            errno = ENOENT;
            return YES;
        }
    }

    // SHADW_DIRFD_ORIGINAL: let the kernel answer.
    return NO;
}

// Classifies a readlink result: absolute targets are checked directly;
// relative targets resolve against the directory CONTAINING the link (that's
// where the kernel resolves them from). A target whose parent directory can't
// be resolved is denied — never exposed unclassified.
static BOOL shdw_readlink_target_restricted(int dirfd, const char* pathname, const char* target) {
    if(target[0] == '/') {
        return [_shadow isCPathRestricted:target];
    }

    NSString* linkPath = nil;

    if(pathname[0] == '/') {
        linkPath = [NSString stringWithUTF8String:pathname];
    } else {
        char parent[PATH_MAX];
        shdw_dirfd_status_t status = shdw_resolve_dirfd_path(dirfd, pathname, parent, sizeof(parent));

        if(status != SHADW_DIRFD_OK) {
            // The link's parent can't be resolved: fail closed. (The
            // unresolvable-dirfd case was already denied by the location
            // check before this helper ran.)
            return YES;
        }

        linkPath = [[NSString stringWithUTF8String:parent] stringByAppendingPathComponent:[NSString stringWithUTF8String:pathname]];
    }

    NSString* joined = [[[linkPath stringByDeletingLastPathComponent]
        stringByAppendingPathComponent:[NSString stringWithUTF8String:target]]
        stringByStandardizingPath];

    return [_shadow isCPathRestricted:[joined fileSystemRepresentation]];
}

static ssize_t (*original_readlinkat)(int dirfd, const char* pathname, char* buf, size_t bufsize);
static ssize_t replaced_readlinkat(int dirfd, const char* pathname, char* buf, size_t bufsize) {
    if(isCallerExternal()) {
        return original_readlinkat(dirfd, pathname, buf, bufsize);
    }

    if(shdw_at_path_denied(dirfd, pathname)) {
        return -1;
    }

    // buf NULL or bufsize 0: stock readlinkat fails (EFAULT/EINVAL); the
    // local-buffer path below must not turn those into a success.
    if(buf == NULL || bufsize == 0) {
        return original_readlinkat(dirfd, pathname, buf, bufsize);
    }

    // Read into a temp buffer first: a link in a safe location can still
    // name a restricted path in its CONTENT, and on denial the caller's
    // buffer must be left untouched.
    char content[PATH_MAX];
    ssize_t result = original_readlinkat(dirfd, pathname, content, sizeof(content));

    if(result != -1 && result < (ssize_t) sizeof(content)) {
        content[result] = '\0';

        if(shdw_readlink_target_restricted(dirfd, pathname, content)) {
            errno = ENOENT;
            return -1;
        }

        size_t copy_len = (size_t) result;

        if(copy_len > bufsize) {
            copy_len = bufsize;
        }

        if(copy_len > 0) {
            memcpy(buf, content, copy_len);
        }

        return (ssize_t) copy_len;
    }

    // ponytail: a link longer than PATH_MAX can't be validated as a string;
    // it can't be a JB indicator path either (those are short), so forward.
    return result;
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

// Shared mount sanitizer: iterates the first `count` records of `buf`,
// REMOVES restricted mounts (f_mntonname or f_mntfromname classified via
// isCPathRestricted), compacts the survivors in place and returns the
// filtered count. The buffer is caller-owned — libc's static mount table is
// never mutated. The stock-represented root record gets MNT_RDONLY in
// f_flags only when `statfsFlags` is YES: statvfs-family f_flag carries only
// ST_* bits (those hooks apply ST_RDONLY themselves). MNT_SNAPSHOT and
// MNT_ROOTFS are preserved exactly as the kernel reported them — never OR'd
// in synthetically (that combination is the jailbreak synthetic-snapshot
// fingerprint).
static int shdw_filter_mounts(struct statfs* buf, int count, BOOL statfsFlags) {
    if(!buf || count <= 0) {
        return count;
    }

    int out = 0;

    for(int i = 0; i < count; i++) {
        struct statfs* rec = &buf[i];

        if([_shadow isCPathRestricted:rec->f_mntonname]
        || [_shadow isCPathRestricted:rec->f_mntfromname]) {
            continue;  // restricted mount: removed, compacted away below
        }

        if(out != i) {
            buf[out] = buf[i];
        }

        if(statfsFlags && strcmp(buf[out].f_mntonname, "/") == 0) {
            buf[out].f_flags |= MNT_RDONLY;
        }

        out++;
    }

    return out;
}

static int (*original_getfsstat)(struct statfs* buf, int bufsize, int flags);
static int replaced_getfsstat(struct statfs* buf, int bufsize, int flags) {
    if(isCallerExternal()) {
        return original_getfsstat(buf, bufsize, flags);
    }

    int result = original_getfsstat(buf, bufsize, flags);

    if(result > 0 && buf && bufsize >= (int) sizeof(struct statfs)) {
        // getfsstat returns the TOTAL entry count; when the caller's buffer
        // is too small only bufsize/sizeof(struct statfs) entries were
        // actually written, so only walk the written ones.
        int written = result;
        int capacity = bufsize / (int) sizeof(struct statfs);

        if(capacity < written) {
            written = capacity;
        }

        int filtered = shdw_filter_mounts(buf, written, YES);

        if(filtered != written) {
            // Report the count that matches the returned records so the
            // caller's resize loop stays consistent. Size-only queries
            // (buf == NULL) keep the kernel's raw total: the records aren't
            // visible to filter, and the full query that follows returns the
            // filtered count, so the loop still terminates.
            return filtered;
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
    // static getmntinfo. Copy, filter the copy, and hand the caller the
    // new buffer (callers that free() the result free our malloc block;
    // callers that don't leak one buffer per call, same as getmntinfo_r).
    size_t bytes = (size_t) result * sizeof(struct statfs);
    struct statfs* copy = (struct statfs *) malloc(bytes);

    if(copy == NULL) {
        return result;
    }

    memcpy(copy, *mntbufp, bytes);

    result = shdw_filter_mounts(copy, result, YES);
    *mntbufp = copy;

    return result;
}

// getmntinfo_r_np (iOS 16+) writes records into caller-provided storage
// instead of libc's static table; the sanitizer runs in place (the caller's
// buffer is ours to compact, same contract as getfsstat). The SDK's fcntl.h
// carries a truncated 2-arg prototype for this symbol, so the real 4-arg
// function is resolved at runtime and never referenced by name.
typedef int (*shdw_getmntinfo_r_np_fn)(struct statfs** mntbufp, int flags, char* buf, int bufsize);

static shdw_getmntinfo_r_np_fn original_getmntinfo_r_np = NULL;

static int shdw_replaced_getmntinfo_r_np(struct statfs** mntbufp, int flags, char* buf, int bufsize) {
    if(isCallerExternal()) {
        return original_getmntinfo_r_np(mntbufp, flags, buf, bufsize);
    }

    int result = original_getmntinfo_r_np(mntbufp, flags, buf, bufsize);

    if(result > 0 && *mntbufp) {
        result = shdw_filter_mounts(*mntbufp, result, YES);
    }

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

    if(result == 0 && buf && shdw_filter_mounts(buf, 1, YES) == 0) {
        // The mount record itself is restricted: deny rather than present it.
        errno = ENOENT;
        return -1;
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

    if(result == 0 && buf && shdw_filter_mounts(buf, 1, YES) == 0) {
        errno = ENOENT;
        return -1;
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

    if(shdw_filter_mounts(&st, 1, NO) == 0) {
        // The mount record itself is restricted: deny the query.
        errno = ENOENT;
        return -1;
    }

    int result = original_statvfs(pathname, buf);

    if(result == 0 && buf && strcmp(st.f_mntonname, "/") == 0) {
        // Mark rootfs read-only. statvfs.f_flag only supports the ST_*
        // constants (ST_RDONLY/ST_NOSUID); the MNT_* bits belong to
        // struct statfs and must not be OR'd in here.
        buf->f_flag |= ST_RDONLY;
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

    if(shdw_filter_mounts(&st, 1, NO) == 0) {
        errno = ENOENT;
        return -1;
    }

    int result = original_fstatvfs(fd, buf);

    if(result == 0 && buf && strcmp(st.f_mntonname, "/") == 0) {
        // Mark rootfs read-only (statvfs carries the flags in f_flag,
        // which only supports the ST_* constants, not MNT_*).
        buf->f_flag |= ST_RDONLY;
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

    if(shdw_at_path_denied(dirfd, pathname)) {
        return -1;
    }

    return original_fstatat(dirfd, pathname, buf, flags);
}

static int (*original_faccessat)(int dirfd, const char* pathname, int mode, int flags);
static int replaced_faccessat(int dirfd, const char* pathname, int mode, int flags) {
    SHADOW_TRIP(pathname, "faccessat");

    if(isCallerExternal()) {
        return original_faccessat(dirfd, pathname, mode, flags);
    }

    if(shdw_at_path_denied(dirfd, pathname)) {
        return -1;
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

            if(resolved_path == NULL) {
                // realpath malloc'd the result; it becomes unreachable once
                // we return NULL — free it first.
                free(result);
            }

            return NULL;
        }

        // The returned path is the fully resolved TARGET: a symlink chain
        // can land in a restricted location even when the input path is
        // not restricted, so check the resolved string as well.
        if([_shadow isCPathRestricted:result]) {
            errno = EACCES;

            if(resolved_path == NULL) {
                free(result);
            }

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

    if(shdw_at_path_denied(dirfd, pathname)) {
        return -1;
    }

    return original_unlinkat(dirfd, pathname, flags);
}

static int (*original_linkat)(int dirfd1, const char* path1, int dirfd2, const char* path2, int flags);
static int replaced_linkat(int dirfd1, const char* path1, int dirfd2, const char* path2, int flags) {
    if(isCallerExternal()) {
        return original_linkat(dirfd1, path1, dirfd2, path2, flags);
    }

    // Both path arguments are resolved against their own dirfd.
    if(shdw_at_path_denied(dirfd1, path1) || shdw_at_path_denied(dirfd2, path2)) {
        return -1;
    }

    return original_linkat(dirfd1, path1, dirfd2, path2, flags);
}

static int (*original_symlinkat)(const char* path1, int dirfd, const char* path2);
static int replaced_symlinkat(const char* path1, int dirfd, const char* path2) {
    if(isCallerExternal()) {
        return original_symlinkat(path1, dirfd, path2);
    }

    // Link LOCATION (path2, resolved against dirfd): same policy as symlink.
    if(shdw_at_path_denied(dirfd, path2)) {
        return -1;
    }

    // Link TARGET (path1): a relative target resolves against the directory
    // containing the link, so classify the joined path, not the raw string.
    if(path1 && path1[0] == '/') {
        if([_shadow isCPathRestricted:path1]) {
            errno = EACCES;
            return -1;
        }
    } else if(path1 && path1[0]) {
        NSString* linkDir = nil;

        if(path2 && path2[0] == '/') {
            linkDir = [[NSString stringWithUTF8String:path2] stringByDeletingLastPathComponent];
        } else {
            char parent[PATH_MAX];
            shdw_dirfd_status_t status = shdw_resolve_dirfd_path(dirfd, path2, parent, sizeof(parent));

            if(status == SHADW_DIRFD_OK) {
                linkDir = [NSString stringWithUTF8String:parent];

                if(path2 && path2[0]) {
                    linkDir = [linkDir stringByAppendingPathComponent:[[NSString stringWithUTF8String:path2] stringByDeletingLastPathComponent]];
                }
            }
        }

        if(linkDir && linkDir.length) {
            NSString* joined = [[linkDir stringByAppendingPathComponent:[NSString stringWithUTF8String:path1]] stringByStandardizingPath];

            if([_shadow isCPathRestricted:[joined fileSystemRepresentation]]) {
                errno = EACCES;
                return -1;
            }
        }
    }

    return original_symlinkat(path1, dirfd, path2);
}

static int (*original_renameat)(int fromfd, const char* from, int tofd, const char* to);
static int replaced_renameat(int fromfd, const char* from, int tofd, const char* to) {
    if(isCallerExternal()) {
        return original_renameat(fromfd, from, tofd, to);
    }

    // Both path arguments are resolved against their own dirfd.
    if(shdw_at_path_denied(fromfd, from) || shdw_at_path_denied(tofd, to)) {
        return -1;
    }

    return original_renameat(fromfd, from, tofd, to);
}

static int (*original_mkdirat)(int dirfd, const char* path, mode_t mode);
static int replaced_mkdirat(int dirfd, const char* path, mode_t mode) {
    if(isCallerExternal()) {
        return original_mkdirat(dirfd, path, mode);
    }

    if(shdw_at_path_denied(dirfd, path)) {
        return -1;
    }

    return original_mkdirat(dirfd, path, mode);
}

static int (*original_utimensat)(int dirfd, const char* path, const struct timespec times[2], int flags);
static int replaced_utimensat(int dirfd, const char* path, const struct timespec times[2], int flags) {
    if(isCallerExternal()) {
        return original_utimensat(dirfd, path, times, flags);
    }

    if(shdw_at_path_denied(dirfd, path)) {
        return -1;
    }

    return original_utimensat(dirfd, path, times, flags);
}

static int (*original_fchmodat)(int dirfd, const char* path, mode_t mode, int flags);
static int replaced_fchmodat(int dirfd, const char* path, mode_t mode, int flags) {
    if(isCallerExternal()) {
        return original_fchmodat(dirfd, path, mode, flags);
    }

    if(shdw_at_path_denied(dirfd, path)) {
        return -1;
    }

    return original_fchmodat(dirfd, path, mode, flags);
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
// Fail the same way stock does (ENOENT — the path doesn't resolve). The
// probe is matched as an exact path COMPONENT under the app's bundle
// directory: a substring match would trip on benign names like
// "notajbrootfile". Deny only when a path component equals ".jbroot" and the
// components before it are exactly the app bundle dir.
static BOOL shdw_is_jbroot_write_probe(const char* pathname, int oflag) {
    if(!pathname || !(oflag & O_CREAT)) {
        return NO;
    }

    NSString* bundlePath = [_shadow bundlePath];

    if(!bundlePath || !bundlePath.length) {
        return NO;
    }

    NSArray* components = [[NSString stringWithUTF8String:pathname] pathComponents];
    NSUInteger count = components.count;

    for(NSUInteger i = 0; i < count; i++) {
        if(![components[i] isEqualToString:@".jbroot"]) {
            continue;
        }

        // The ".jbroot" component's parent must be the app bundle directory.
        NSString* parent = [[NSString pathWithComponents:[components subarrayWithRange:NSMakeRange(0, i)]] stringByStandardizingPath];

        if([parent isEqualToString:bundlePath]) {
            return YES;
        }
    }

    return NO;
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

    if(shdw_at_path_denied(dirfd, pathname)) {
        return -1;
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
    {
        // getmntinfo_r_np is an iOS 16+ export; resolve at runtime and skip
        // cleanly on systems that don't provide it.
        void* getmntinfo_r_np_sym = dlsym(RTLD_DEFAULT, "getmntinfo_r_np");

        if(getmntinfo_r_np_sym) {
            MSHookFunction(getmntinfo_r_np_sym, shdw_replaced_getmntinfo_r_np, (void **) &original_getmntinfo_r_np);
        }
    }
    MSHookFunction(getattrlist, replaced_getattrlist, (void **) &original_getattrlist);
    MSHookFunction(symlink, replaced_symlink, (void **) &original_symlink);
    MSHookFunction(rename, replaced_rename, (void **) &original_rename);
    MSHookFunction(remove, replaced_remove, (void **) &original_remove);
    MSHookFunction(unlink, replaced_unlink, (void **) &original_unlink);
    MSHookFunction(unlinkat, replaced_unlinkat, (void **) &original_unlinkat);
    MSHookFunction(linkat, replaced_linkat, (void **) &original_linkat);
    MSHookFunction(symlinkat, replaced_symlinkat, (void **) &original_symlinkat);
    MSHookFunction(renameat, replaced_renameat, (void **) &original_renameat);
    MSHookFunction(mkdirat, replaced_mkdirat, (void **) &original_mkdirat);

    if(@available(iOS 11, *)) {
        // utimensat is iOS 11+; skip on older systems.
        MSHookFunction(utimensat, replaced_utimensat, (void **) &original_utimensat);
    }

    MSHookFunction(fchmodat, replaced_fchmodat, (void **) &original_fchmodat);
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
