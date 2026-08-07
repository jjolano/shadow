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
// (a miss just re-resolves — results stay identical). A valid directory
// vnode whose path can't be resolved is cached as DENIED: entries are hidden
// (fail closed) rather than exposed unfiltered — the old code cached the
// F_GETPATH failure as "allowed".
// TODO(plan-wave-A): invalidate on ruleset generation.
#define SHADW_READDIR_CACHE_SIZE 16

typedef struct {
    DIR* dirp;
    CFDictionaryRef options; // retained; NULL when no filtering applies
    BOOL denied;             // valid dir vnode, path unresolvable: hide entries
} shdw_readdir_cache_entry_t;

static shdw_readdir_cache_entry_t shdw_readdir_cache[SHADW_READDIR_CACHE_SIZE];

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
            shdw_readdir_cache[i].denied = NO;
            break;
        }
    }
}

// Returns a retained options dict for the DIR*'s parent path (caller must
// CFRelease), or NULL when no filtering applies. Sets *denied when the DIR*
// is a valid directory vnode whose path can't be resolved: entries must be
// hidden (fail closed). *denied is never set for an invalid DIR* — the
// original readdir fails on its own with the genuine EBADF.
static NSDictionary* shdw_readdir_cache_options(DIR* dirp, BOOL* denied) {
    os_unfair_lock_lock(&shdw_readdir_cache_lock);

    *denied = NO;
    NSDictionary* result = nil;
    BOOL cached = NO;

    for(NSUInteger i = 0; i < SHADW_READDIR_CACHE_SIZE; i++) {
        if(shdw_readdir_cache[i].dirp == dirp) {
            cached = YES;

            if(shdw_readdir_cache[i].options) {
                result = (__bridge NSDictionary*)CFRetain(shdw_readdir_cache[i].options);
            }

            *denied = shdw_readdir_cache[i].denied;
            break;
        }
    }

    if(!cached) {
        char pathname[PATH_MAX];
        NSDictionary* options = nil;
        BOOL deniedEntry = NO;

        if(fcntl(dirfd(dirp), F_GETPATH, pathname) != -1) {
            options = @{kShadowRestrictionWorkingDir : [NSString stringWithUTF8String:pathname]};
            result = (__bridge NSDictionary*)CFRetain((__bridge CFDictionaryRef)options);
        } else if(errno != EBADF) {
            // Valid vnode whose path can't be named: fail closed.
            deniedEntry = YES;
            *denied = YES;
        }

        // errno == EBADF: invalid DIR*; the original readdir fails on its own.

        // Evict the next slot (may drop a live DIR*'s entry; a miss just re-resolves).
        NSUInteger slot = shdw_readdir_cache_next;
        shdw_readdir_cache_next = (shdw_readdir_cache_next + 1) % SHADW_READDIR_CACHE_SIZE;

        if(shdw_readdir_cache[slot].options) {
            CFRelease(shdw_readdir_cache[slot].options);
        }

        shdw_readdir_cache[slot].dirp = dirp;
        shdw_readdir_cache[slot].options = options ? CFRetain((__bridge CFDictionaryRef)options) : NULL;
        shdw_readdir_cache[slot].denied = deniedEntry;
    }

    os_unfair_lock_unlock(&shdw_readdir_cache_lock);
    return result;
}

static int (*original_readdir_r)(DIR* dirp, struct dirent* entry, struct dirent** oresult);
static int replaced_readdir_r(DIR* dirp, struct dirent* entry, struct dirent** oresult) {
    if(isCallerExternal()) {
        return original_readdir_r(dirp, entry, oresult);
    }

    BOOL denied = NO;
    NSDictionary* options = shdw_readdir_cache_options(dirp, &denied);

    if(denied) {
        // Fail closed: an unresolvable directory exposes nothing.
        if(oresult) {
            *oresult = NULL;
        }

        return 0;
    }

    int result = original_readdir_r(dirp, entry, oresult);
    
    if(result == 0 && *oresult) {
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

    BOOL denied = NO;
    NSDictionary* options = shdw_readdir_cache_options(dirp, &denied);

    if(denied) {
        // Fail closed: an unresolvable directory exposes nothing.
        return NULL;
    }

    struct dirent* result = original_readdir(dirp);
    
    if(result && options) {
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

// Sanitized PATH storage: thread-local so the returned pointer keeps getenv's
// documented lifetime (valid until the next getenv call on this thread) and
// one thread can't overwrite another's value.
static _Thread_local char* shdw_getenv_path_storage = NULL;
static _Thread_local size_t shdw_getenv_path_capacity = 0;

// Removes jailbreak components from a PATH value (/var/jb bootstrap and
// preboot roots — stock iOS PATH has neither). Returns the original pointer
// when nothing needed removing, otherwise a sanitized copy in thread-local
// storage.
static char* shdw_getenv_sanitized_path(const char* value) {
    NSArray* parts = [[NSString stringWithUTF8String:value] componentsSeparatedByString:@":"];
    NSMutableArray* kept = [NSMutableArray arrayWithCapacity:parts.count];

    for(NSString* part in parts) {
        if([part hasPrefix:@"/var/jb"]
        || [part hasPrefix:@"/private/preboot"]
        || [part hasPrefix:@"/preboot"]) {
            continue;
        }

        [kept addObject:part];
    }

    if(kept.count == parts.count) {
        return (char*) value;
    }

    NSString* joined = [kept componentsJoinedByString:@":"];
    size_t len = joined.length + 1;

    if(len > shdw_getenv_path_capacity) {
        char* grown = realloc(shdw_getenv_path_storage, len);

        if(!grown) {
            // OOM: fall back to the original value rather than returning a
            // truncated path.
            return (char*) value;
        }

        shdw_getenv_path_storage = grown;
        shdw_getenv_path_capacity = len;
    }

    strcpy(shdw_getenv_path_storage, joined.UTF8String);
    return shdw_getenv_path_storage;
}

static char* (*original_getenv)(const char* name);
static char* replaced_getenv(const char* name) {
    if(isCallerExternal()) {
        return original_getenv(name);
    }

    char* result = original_getenv(name);

    if(!result || !name || !name[0]) {
        return result;
    }

    // Stock iOS never has these set; their presence is the jailbreak signal
    // a detector reads back from getenv. DYLD_* covers INSERT_LIBRARIES and
    // every search-path knob.
    if(strncmp(name, "DYLD_", 5) == 0
    || strncmp(name, "JAILBREAKD_", 11) == 0
    || strcmp(name, "_MSSafeMode") == 0
    || strcmp(name, "_SafeMode") == 0
    || strcmp(name, "_SubstituteSafeMode") == 0) {
        return NULL;
    }

    if(strcmp(name, "PATH") == 0) {
        return shdw_getenv_sanitized_path(result);
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

// libproc.h isn't shipped in the theos SDK; declare the one symbol we need
// (proc_pidpath is a stable libSystem export).
extern int proc_pidpath(int pid, void* buffer, uint32_t buffersize);

static int (*original_sysctl)(int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen);

// Classifies a process as restricted (jailbreak daemon) by its executable
// path. proc_pidpath is visible for other pids on iOS; when it fails (EPERM)
// the process can't be classified and is kept — denying legitimate processes
// would corrupt the process count on stock devices.
static BOOL shdw_proc_is_restricted(pid_t pid) {
    char path[PATH_MAX];

    if(proc_pidpath(pid, path, sizeof(path)) > 0) {
        return [_shadow isCPathRestricted:path];
    }

    return NO;
}

// KERN_PROC_ALL read: returns the process list with restricted processes
// removed and the list compacted, using stock sysctl size semantics
// (size-only query → filtered byte count in *oldlenp; short buffer → ENOMEM
// with the required size in *oldlenp). The MIB is normalized to the canonical
// 3 elements before touching the kernel.
static int shdw_sysctl_proc_all(void* oldp, size_t* oldlenp) {
    int procMIB[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };

    size_t capacity = 0;
    int ret = original_sysctl(procMIB, 3, NULL, &capacity, NULL, 0);

    if(ret != 0) {
        return ret;  // kernel owns the error and *oldlenp
    }

    // Slack for process churn between the size and full queries.
    capacity += sizeof(struct kinfo_proc) * 8;

    struct kinfo_proc* procs = malloc(capacity);

    if(!procs) {
        errno = ENOMEM;
        return -1;
    }

    size_t actual = capacity;
    ret = original_sysctl(procMIB, 3, procs, &actual, NULL, 0);

    if(ret != 0 && errno == ENOMEM) {
        // Churn outgrew the first buffer: retry once with the kernel's size.
        free(procs);
        capacity = actual;
        procs = malloc(capacity);

        if(!procs) {
            errno = ENOMEM;
            return -1;
        }

        actual = capacity;
        ret = original_sysctl(procMIB, 3, procs, &actual, NULL, 0);
    }

    if(ret != 0) {
        free(procs);
        return ret;
    }

    int count = (int)(actual / sizeof(struct kinfo_proc));
    int out = 0;

    for(int i = 0; i < count; i++) {
        struct kinfo_proc* p = &procs[i];

        if(p->kp_proc.p_pid == getpid()) {
            // Never report our own trace flags.
            p->kp_proc.p_flag &= ~P_TRACED;
            p->kp_proc.p_flag &= ~P_SELECT;
        } else if(shdw_proc_is_restricted(p->kp_proc.p_pid)) {
            continue;  // jailbreak daemon: removed from the list
        }

        if(out != i) {
            procs[out] = procs[i];
        }

        out++;
    }

    size_t needed = (size_t) out * sizeof(struct kinfo_proc);

    if(oldp == NULL) {
        // Size-only query: report the filtered byte count.
        *oldlenp = needed;
        free(procs);
        return 0;
    }

    if(*oldlenp < needed) {
        // Short buffer: stock sysctl semantics (ENOMEM + required size).
        *oldlenp = needed;
        free(procs);
        errno = ENOMEM;
        return -1;
    }

    memcpy(oldp, procs, needed);
    *oldlenp = needed;
    free(procs);
    return 0;
}

static int replaced_sysctl(int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen) {
    if(name == NULL || namelen == 0) {
        return original_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }

    // KERN_PROC_ALL is a 3-element MIB (some callers append a legacy 4th
    // zero element). Every index into name[] is bounds-checked.
    BOOL isProcAll = name[0] == CTL_KERN
        && namelen >= 3
        && name[1] == KERN_PROC
        && name[2] == KERN_PROC_ALL
        && (namelen == 3 || (namelen == 4 && name[3] == 0));

    BOOL isOwnPid = name[0] == CTL_KERN
        && namelen == 4
        && name[1] == KERN_PROC
        && name[2] == KERN_PROC_PID
        && name[3] == getpid();

    int ret;

    if(isProcAll && newp == NULL && oldlenp != NULL) {
        ret = shdw_sysctl_proc_all(oldp, oldlenp);
    } else {
        ret = original_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }

    // Remove trace flags from our own process record — only on valid success
    // and only when the caller's buffer actually carries the record.
    if(ret == 0 && isOwnPid && oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
        struct kinfo_proc* p = (struct kinfo_proc*) oldp;

        if(p->kp_proc.p_flag & P_TRACED) {
            p->kp_proc.p_flag &= ~P_TRACED;
        }

        if(p->kp_proc.p_flag & P_SELECT) {
            p->kp_proc.p_flag &= ~P_SELECT;
        }
    }

    return ret;
}

static pid_t (*original_getppid)(void);
static pid_t replaced_getppid(void) {
    if(isCallerExternal()) {
        // Tweak-internal callers get the real parent (cross-tweak
        // regression); the app/detector sees the stock answer for a process
        // without a debugger parent.
        return original_getppid();
    }

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

// --- stat64 family + protected-open variants ---------------------------------
// These are legacy/compat exports: the stat64 family and open_dprotected_np/
// openat_dprotected_np are absent on modern iOS (64-bit stat IS stat64), and
// openat_authenticated_np is not in the SDK at all. All seven are resolved at
// runtime and skipped cleanly when libSystem doesn't export them; policies
// mirror their stat/lstat/fd/*at/open/openat counterparts with the 64-bit
// struct layouts, and the protection args pass through untouched.

struct ad_open_auth;  // <sys/open.h> is not in the theos SDK

// struct stat64 is not visible in this build configuration: the SDK guards it
// behind feature macros and omits it entirely on LP64 platforms where struct
// stat already IS the 64-bit layout. Define the 32-bit layout ourselves
// (mirrors xnu's __DARWIN_STRUCT_STAT64) and alias struct stat on LP64.
#if defined(__LP64__)
#define shdw_stat64_t struct stat
#else
struct shdw_stat64 {
    __int32_t    st_dev;
    __uint16_t   st_mode;
    __uint16_t   st_nlink;
    __uint64_t   st_ino;
    __uint32_t   st_uid;
    __uint32_t   st_gid;
    __int32_t    st_rdev;
    struct timespec st_atimespec;
    struct timespec st_mtimespec;
    struct timespec st_ctimespec;
    struct timespec st_birthtimespec;
    __int64_t    st_size;
    __int64_t    st_blocks;
    __int32_t    st_blksize;
    __uint32_t   st_flags;
    __uint32_t   st_gen;
    __int32_t    st_lspare;
    __int64_t    st_qspare[2];
};
#define shdw_stat64_t struct shdw_stat64
#endif

static int (*original_stat64)(const char* pathname, shdw_stat64_t* buf);
static int replaced_stat64(const char* pathname, shdw_stat64_t* buf) {
    SHADOW_TRIP(pathname, "stat64");

    int result = original_stat64(pathname, buf);

    if(result != -1 && !isCallerExternal() && [_shadow isCPathRestricted:pathname]) {
        if(buf) {
            memset(buf, 0, sizeof(shdw_stat64_t));
        }

        errno = ENOENT;
        return -1;
    }

    return result;
}

static int (*original_lstat64)(const char* pathname, shdw_stat64_t* buf);
static int replaced_lstat64(const char* pathname, shdw_stat64_t* buf) {
    SHADOW_TRIP(pathname, "lstat64");

    if(isCallerExternal()) {
        return original_lstat64(pathname, buf);
    }

    shdw_stat64_t _buf;
    int result = original_lstat64(pathname, &_buf);

    if(result == 0) {
        NSString* path = [NSString stringWithUTF8String:pathname];

        // Only use resolve flag if target is not a symlink (link-LOCATION
        // check, same policy as lstat).
        if([_shadow isPathRestricted:path options:@{
            kShadowRestrictionEnableResolve : @(!S_ISLNK(_buf.st_mode)),
            kShadowRestrictionNoFollow : @YES
        }]) {
            errno = ENOENT;
            return -1;
        }

        // NULL caller buffer keeps stock semantics (EFAULT from the kernel).
        if(buf == NULL) {
            return original_lstat64(pathname, NULL);
        }

        // Only copy on success: on failure _buf is uninitialized stack.
        memcpy(buf, &_buf, sizeof(shdw_stat64_t));
    }

    return result;
}

static int (*original_fstat64)(int fd, shdw_stat64_t* buf);
static int replaced_fstat64(int fd, shdw_stat64_t* buf) {
    if(isCallerExternal()) {
        return original_fstat64(fd, buf);
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

    return original_fstat64(fd, buf);
}

static int (*original_fstatat64)(int dirfd, const char* pathname, shdw_stat64_t* buf, int flags);
static int replaced_fstatat64(int dirfd, const char* pathname, shdw_stat64_t* buf, int flags) {
    SHADOW_TRIP(pathname, "fstatat64");

    if(isCallerExternal()) {
        return original_fstatat64(dirfd, pathname, buf, flags);
    }

    if(shdw_at_path_denied(dirfd, pathname)) {
        return -1;
    }

    return original_fstatat64(dirfd, pathname, buf, flags);
}

static int (*original_open_dprotected_np)(const char* path, int flags, int class, int dpflags, ...);
static int replaced_open_dprotected_np(const char* path, int flags, int class, int dpflags, ...) {
    SHADOW_TRIP(path, "open_dprotected_np");

    mode_t mode = 0;

    // Same vararg rule as open: the mode argument exists only with O_CREAT.
    if(flags & O_CREAT) {
        va_list args;
        va_start(args, dpflags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }

    if(!isCallerExternal() && shdw_is_jbroot_write_probe(path, flags)) {
        errno = ENOENT;
        return -1;
    }

    if(isCallerExternal() || ![_shadow isCPathRestricted:path]) {
        if(flags & O_CREAT) {
            return original_open_dprotected_np(path, flags, class, dpflags, mode);
        }

        return original_open_dprotected_np(path, flags, class, dpflags);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_openat_dprotected_np)(int dirfd, const char* path, int flags, int class, int dpflags, ...);
static int replaced_openat_dprotected_np(int dirfd, const char* path, int flags, int class, int dpflags, ...) {
    SHADOW_TRIP(path, "openat_dprotected_np");

    mode_t mode = 0;

    if(flags & O_CREAT) {
        va_list args;
        va_start(args, dpflags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }

    if(isCallerExternal()) {
        if(flags & O_CREAT) {
            return original_openat_dprotected_np(dirfd, path, flags, class, dpflags, mode);
        }

        return original_openat_dprotected_np(dirfd, path, flags, class, dpflags);
    }

    if(shdw_is_jbroot_write_probe(path, flags)) {
        errno = ENOENT;
        return -1;
    }

    if(shdw_at_path_denied(dirfd, path)) {
        return -1;
    }

    if(flags & O_CREAT) {
        return original_openat_dprotected_np(dirfd, path, flags, class, dpflags, mode);
    }

    return original_openat_dprotected_np(dirfd, path, flags, class, dpflags);
}

static int (*original_openat_authenticated_np)(int dirfd, const char* path, struct ad_open_auth* auth, int flags, ...);
static int replaced_openat_authenticated_np(int dirfd, const char* path, struct ad_open_auth* auth, int flags, ...) {
    SHADOW_TRIP(path, "openat_authenticated_np");

    mode_t mode = 0;

    if(flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }

    if(isCallerExternal()) {
        if(flags & O_CREAT) {
            return original_openat_authenticated_np(dirfd, path, auth, flags, mode);
        }

        return original_openat_authenticated_np(dirfd, path, auth, flags);
    }

    if(shdw_is_jbroot_write_probe(path, flags)) {
        errno = ENOENT;
        return -1;
    }

    if(shdw_at_path_denied(dirfd, path)) {
        return -1;
    }

    if(flags & O_CREAT) {
        return original_openat_authenticated_np(dirfd, path, auth, flags, mode);
    }

    return original_openat_authenticated_np(dirfd, path, auth, flags);
}

void shadowhook_libc(HKSubstitutor* hooks) {
    [hooks hookFunction:access withReplacement:replaced_access outOldPtr:(void **) &original_access];
    [hooks hookFunction:chdir withReplacement:replaced_chdir outOldPtr:(void **) &original_chdir];
    [hooks hookFunction:chroot withReplacement:replaced_chroot outOldPtr:(void **) &original_chroot];
    [hooks hookFunction:creat withReplacement:replaced_creat outOldPtr:(void **) &original_creat];
    [hooks hookFunction:statfs withReplacement:replaced_statfs outOldPtr:(void **) &original_statfs];
    [hooks hookFunction:fstatfs withReplacement:replaced_fstatfs outOldPtr:(void **) &original_fstatfs];
    [hooks hookFunction:statvfs withReplacement:replaced_statvfs outOldPtr:(void **) &original_statvfs];
    [hooks hookFunction:fstatvfs withReplacement:replaced_fstatvfs outOldPtr:(void **) &original_fstatvfs];
    [hooks hookFunction:stat withReplacement:replaced_stat outOldPtr:(void **) &original_stat];
    [hooks hookFunction:lstat withReplacement:replaced_lstat outOldPtr:(void **) &original_lstat];
    [hooks hookFunction:faccessat withReplacement:replaced_faccessat outOldPtr:(void **) &original_faccessat];
    [hooks hookFunction:readdir_r withReplacement:replaced_readdir_r outOldPtr:(void **) &original_readdir_r];
    [hooks hookFunction:readdir withReplacement:replaced_readdir outOldPtr:(void **) &original_readdir];
    [hooks hookFunction:closedir withReplacement:replaced_closedir outOldPtr:(void **) &original_closedir];
    [hooks hookFunction:fopen withReplacement:replaced_fopen outOldPtr:(void **) &original_fopen];
    [hooks hookFunction:freopen withReplacement:replaced_freopen outOldPtr:(void **) &original_freopen];
    [hooks hookFunction:realpath withReplacement:replaced_realpath outOldPtr:(void **) &original_realpath];
    [hooks hookFunction:readlink withReplacement:replaced_readlink outOldPtr:(void **) &original_readlink];
    [hooks hookFunction:readlinkat withReplacement:replaced_readlinkat outOldPtr:(void **) &original_readlinkat];
    [hooks hookFunction:link withReplacement:replaced_link outOldPtr:(void **) &original_link];
    // [hooks hookFunction:scandir withReplacement:replaced_scandir outOldPtr:(void **) &original_scandir];
    [hooks hookFunction:getmntinfo withReplacement:replaced_getmntinfo outOldPtr:(void **) &original_getmntinfo];
    {
        // getmntinfo_r_np is an iOS 16+ export; resolve at runtime and skip
        // cleanly on systems that don't provide it.
        void* getmntinfo_r_np_sym = dlsym(RTLD_DEFAULT, "getmntinfo_r_np");

        if(getmntinfo_r_np_sym) {
            [hooks hookFunction:getmntinfo_r_np_sym withReplacement:shdw_replaced_getmntinfo_r_np outOldPtr:(void **) &original_getmntinfo_r_np];
        }
    }
    [hooks hookFunction:getattrlist withReplacement:replaced_getattrlist outOldPtr:(void **) &original_getattrlist];
    [hooks hookFunction:symlink withReplacement:replaced_symlink outOldPtr:(void **) &original_symlink];
    [hooks hookFunction:rename withReplacement:replaced_rename outOldPtr:(void **) &original_rename];
    [hooks hookFunction:remove withReplacement:replaced_remove outOldPtr:(void **) &original_remove];
    [hooks hookFunction:unlink withReplacement:replaced_unlink outOldPtr:(void **) &original_unlink];
    [hooks hookFunction:unlinkat withReplacement:replaced_unlinkat outOldPtr:(void **) &original_unlinkat];
    [hooks hookFunction:linkat withReplacement:replaced_linkat outOldPtr:(void **) &original_linkat];
    [hooks hookFunction:symlinkat withReplacement:replaced_symlinkat outOldPtr:(void **) &original_symlinkat];
    [hooks hookFunction:renameat withReplacement:replaced_renameat outOldPtr:(void **) &original_renameat];
    [hooks hookFunction:mkdirat withReplacement:replaced_mkdirat outOldPtr:(void **) &original_mkdirat];

    if(@available(iOS 11, *)) {
        // utimensat is iOS 11+; skip on older systems.
        [hooks hookFunction:utimensat withReplacement:replaced_utimensat outOldPtr:(void **) &original_utimensat];
    }

    [hooks hookFunction:fchmodat withReplacement:replaced_fchmodat outOldPtr:(void **) &original_fchmodat];
    [hooks hookFunction:rmdir withReplacement:replaced_rmdir outOldPtr:(void **) &original_rmdir];
    [hooks hookFunction:pathconf withReplacement:replaced_pathconf outOldPtr:(void **) &original_pathconf];
    [hooks hookFunction:fpathconf withReplacement:replaced_fpathconf outOldPtr:(void **) &original_fpathconf];
    [hooks hookFunction:utimes withReplacement:replaced_utimes outOldPtr:(void **) &original_utimes];
    [hooks hookFunction:futimes withReplacement:replaced_futimes outOldPtr:(void **) &original_futimes];
    [hooks hookFunction:fchdir withReplacement:replaced_fchdir outOldPtr:(void **) &original_fchdir];
    [hooks hookFunction:getfsstat withReplacement:replaced_getfsstat outOldPtr:(void **) &original_getfsstat];
    [hooks hookFunction:fstat withReplacement:replaced_fstat outOldPtr:(void **) &original_fstat];
    [hooks hookFunction:fstatat withReplacement:replaced_fstatat outOldPtr:(void **) &original_fstatat];
}

void shadowhook_libc_envvar(HKSubstitutor* hooks) {
    [hooks hookFunction:getenv withReplacement:replaced_getenv outOldPtr:(void **) &original_getenv];
}

void shadowhook_libc_lowlevel(HKSubstitutor* hooks) {
    [hooks hookFunction:open withReplacement:replaced_open outOldPtr:(void **) &original_open];
    [hooks hookFunction:openat withReplacement:replaced_openat outOldPtr:(void **) &original_openat];
    [hooks hookFunction:__opendir2 withReplacement:replaced___opendir2 outOldPtr:(void **) &original___opendir2];

    // The stat64 family and protected-open variants are not exported on
    // modern iOS; resolve at runtime and skip cleanly when absent.
    struct { const char* name; void* replacement; void** outOld; } shdw_lowlevel_symbols[] = {
        { "stat64",                    (void*) replaced_stat64,                    (void**) &original_stat64 },
        { "lstat64",                   (void*) replaced_lstat64,                   (void**) &original_lstat64 },
        { "fstat64",                   (void*) replaced_fstat64,                   (void**) &original_fstat64 },
        { "fstatat64",                 (void*) replaced_fstatat64,                 (void**) &original_fstatat64 },
        { "open_dprotected_np",        (void*) replaced_open_dprotected_np,        (void**) &original_open_dprotected_np },
        { "openat_dprotected_np",      (void*) replaced_openat_dprotected_np,      (void**) &original_openat_dprotected_np },
        { "openat_authenticated_np",   (void*) replaced_openat_authenticated_np,   (void**) &original_openat_authenticated_np },
    };

    for(size_t i = 0; i < sizeof(shdw_lowlevel_symbols) / sizeof(shdw_lowlevel_symbols[0]); i++) {
        void* target = dlsym(RTLD_DEFAULT, shdw_lowlevel_symbols[i].name);

        if(target) {
            [hooks hookFunction:target withReplacement:shdw_lowlevel_symbols[i].replacement outOldPtr:shdw_lowlevel_symbols[i].outOld];
        }
    }
}

void shadowhook_libc_antidebugging(HKSubstitutor* hooks) {
    [hooks hookFunction:ptrace withReplacement:replaced_ptrace outOldPtr:(void **) &original_ptrace];
    [hooks hookFunction:sysctl withReplacement:replaced_sysctl outOldPtr:(void **) &original_sysctl];
    [hooks hookFunction:getppid withReplacement:replaced_getppid outOldPtr:(void **) &original_getppid];
}
