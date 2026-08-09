#import "hooks.h"
#import "filters.h"

#import <string.h>
#import <stdlib.h>
#import <os/lock.h>
#import <sys/xattr.h>
#import <sys/resource.h>
#import <sys/attr.h>
#import <sys/snapshot.h>

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
#define SHADOW_TRIP(pathname, kind, ext) \
    if(ext && shdw_is_jb_probe(pathname)) { \
        shdw_detector_detected(kind); \
    }

static int (*original_access)(const char* pathname, int mode);
static int replaced_access(const char* pathname, int mode) {
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "access", ext);

    int result = original_access(pathname, mode);

    if(result != -1 && ext && [_shadow isCPathRestricted:pathname]) {
        errno = ENOENT;
        return -1;
    }

    return result;
}

static ssize_t (*original_readlink)(const char* pathname, char* buf, size_t bufsize);
static ssize_t replaced_readlink(const char* pathname, char* buf, size_t bufsize) {
    if(!isCallerExternal()) {
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
// hook site — this helper is never reached for Shadow-internal callers.
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

// fd→path cache for the fd-based hooks (fstat/fstatfs/fstatvfs/fpathconf/
// futimes/fchdir/fgetxattr/flistxattr/fgetattrlist): F_GETPATH is a syscall
// per call, and the fstat family runs on every fd touch. The path is resolved
// once per fd and cached; the close hook invalidates the entry, so a reused
// fd can never inherit a stale path. Fixed-size table, round-robin eviction —
// a miss just re-resolves. The lock is never held across isCPathRestricted
// (an ObjC call that could re-enter hooked code); F_GETPATH itself runs under
// the lock so a close+reuse race can't store a stale entry.
#define SHADW_FD_CACHE_SIZE 16

typedef struct {
    int fd;
    char path[PATH_MAX];
    BOOL valid;  // F_GETPATH succeeded (fd has a nameable path)
} shdw_fd_cache_entry_t;

static shdw_fd_cache_entry_t shdw_fd_cache[SHADW_FD_CACHE_SIZE];
static NSUInteger shdw_fd_cache_next = 0;
static os_unfair_lock shdw_fd_cache_lock = OS_UNFAIR_LOCK_INIT;

// The close hook is installed by whichever group installs first (libc or
// libc_lowlevel — both use the fd cache); the guard keeps the second group
// from double-hooking close on the same substitutor.
static BOOL shdw_close_hooked = NO;

// Returns YES when the fd's path is restricted. stdio descriptors are exempt
// (they never carry a restricted path and F_GETPATH on them is noise).
static BOOL shdw_fd_path_restricted(int fd) {
    if(fd == fileno(stderr) || fd == fileno(stdout) || fd == fileno(stdin)) {
        return NO;
    }

    char pathname[PATH_MAX];
    BOOL valid = NO;

    os_unfair_lock_lock(&shdw_fd_cache_lock);

    for(NSUInteger i = 0; i < SHADW_FD_CACHE_SIZE; i++) {
        if(shdw_fd_cache[i].fd == fd) {
            valid = shdw_fd_cache[i].valid;

            if(valid) {
                strlcpy(pathname, shdw_fd_cache[i].path, sizeof(pathname));
            }

            os_unfair_lock_unlock(&shdw_fd_cache_lock);
            return valid ? [_shadow isCPathRestricted:pathname] : NO;
        }
    }

    valid = fcntl(fd, F_GETPATH, pathname) != -1;

    NSUInteger slot = shdw_fd_cache_next;
    shdw_fd_cache_next = (shdw_fd_cache_next + 1) % SHADW_FD_CACHE_SIZE;

    shdw_fd_cache[slot].fd = fd;
    shdw_fd_cache[slot].valid = valid;

    if(valid) {
        strlcpy(shdw_fd_cache[slot].path, pathname, sizeof(shdw_fd_cache[slot].path));
    }

    os_unfair_lock_unlock(&shdw_fd_cache_lock);

    return valid ? [_shadow isCPathRestricted:pathname] : NO;
}

static int (*original_close)(int fd);
static int replaced_close(int fd) {
    os_unfair_lock_lock(&shdw_fd_cache_lock);

    for(NSUInteger i = 0; i < SHADW_FD_CACHE_SIZE; i++) {
        if(shdw_fd_cache[i].fd == fd) {
            shdw_fd_cache[i].fd = -1;
            shdw_fd_cache[i].valid = NO;
            break;
        }
    }

    os_unfair_lock_unlock(&shdw_fd_cache_lock);
    return original_close(fd);
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
    if(!isCallerExternal()) {
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
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_chdir(pathname);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_fchdir)(int fd);
static int replaced_fchdir(int fd) {
    if(!isCallerExternal()) {
        return original_fchdir(fd);
    }

    if(shdw_fd_path_restricted(fd)) {
        errno = EBADF;
        return -1;
    }

    return original_fchdir(fd);
}

static int (*original_chroot)(const char* pathname);
static int replaced_chroot(const char* pathname) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_chroot(pathname);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_creat)(const char* pathname, mode_t mode);
static int replaced_creat(const char* pathname, mode_t mode) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
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

        // Per-record decision lives in filters.h (pure, harness-testable);
        // the isCPathRestricted verdicts are computed here because they need
        // the Objective-C engine.
        int restricted = [_shadow isCPathRestricted:rec->f_mntonname]
            || [_shadow isCPathRestricted:rec->f_mntfromname];

        if(!shdw_mount_filter(rec->f_mntonname, rec->f_mntfromname,
            (uint32_t*) &rec->f_flags, statfsFlags, restricted)) {
            continue;  // restricted mount: removed, compacted away below
        }

        if(out != i) {
            buf[out] = buf[i];
        }

        out++;
    }

    return out;
}

static int (*original_getfsstat)(struct statfs* buf, int bufsize, int flags);
static int replaced_getfsstat(struct statfs* buf, int bufsize, int flags) {
    if(!isCallerExternal()) {
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

// Process-wide filter buffer for getmntinfo. The API's storage is static
// (stock libc keeps a static mount table that the next call may overwrite),
// so one realloc'd buffer matches that contract with zero per-call leaks —
// stock callers never free the returned table. Like stock getmntinfo, this
// is intentionally not thread-safe (same overwrite-on-next-call semantics).
static struct statfs* shdw_getmntinfo_buf = NULL;
static size_t shdw_getmntinfo_cap = 0;

static int replaced_getmntinfo(struct statfs** mntbufp, int flags) {
    if(!isCallerExternal()) {
        return original_getmntinfo(mntbufp, flags);
    }

    int result = original_getmntinfo(mntbufp, flags);

    if(result <= 0 || *mntbufp == NULL) {
        return result;
    }

    // *mntbufp points at libc's static mount table: never mutate it in
    // place — the mangled entries would leak to the next caller of libc's
    // static getmntinfo. Filter into our own static buffer instead.
    size_t bytes = (size_t) result * sizeof(struct statfs);

    if(bytes > shdw_getmntinfo_cap) {
        struct statfs* grown = (struct statfs *) realloc(shdw_getmntinfo_buf, bytes);

        if(grown == NULL) {
            return result;  // OOM: hand back the unfiltered stock table
        }

        shdw_getmntinfo_buf = grown;
        shdw_getmntinfo_cap = bytes;
    }

    memcpy(shdw_getmntinfo_buf, *mntbufp, bytes);

    result = shdw_filter_mounts(shdw_getmntinfo_buf, result, YES);
    *mntbufp = shdw_getmntinfo_buf;

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
    if(!isCallerExternal()) {
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
    if(!isCallerExternal()) {
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
    if(!isCallerExternal()) {
        return original_fstatfs(fd, buf);
    }

    if(shdw_fd_path_restricted(fd)) {
        errno = EBADF;
        return -1;
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
    if(!isCallerExternal()) {
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
    if(!isCallerExternal()) {
        return original_fstatvfs(fd, buf);
    }

    // use fstatfs to get f_mntonname; original version so the fd/mount
    // restriction checks run once here instead of via the hooked fstatfs
    struct statfs st;

    if(shdw_fd_path_restricted(fd)) {
        errno = EBADF;
        return -1;
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
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "stat", ext);

    int result = original_stat(pathname, buf);

    if(result != -1 && ext && [_shadow isCPathRestricted:pathname]) {
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
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "lstat", ext);

    if(!ext) {
        return original_lstat(pathname, buf);
    }

    // A NULL caller buffer keeps stock semantics: lstat(path, NULL) fails
    // with EFAULT. Replay it before classification so a restricted path is
    // answered with the stock EFAULT for the malformed call, not ENOENT.
    if(buf == NULL) {
        return original_lstat(pathname, NULL);
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

        // Only copy on success: on failure _buf is uninitialized stack.
        memcpy(buf, &_buf, sizeof(struct stat));
    }

    return result;
}

static int (*original_fstat)(int fd, struct stat* buf);
static int replaced_fstat(int fd, struct stat* buf) {
    if(!isCallerExternal()) {
        return original_fstat(fd, buf);
    }

    if(shdw_fd_path_restricted(fd)) {
        errno = EBADF;
        return -1;
    }

    return original_fstat(fd, buf);
}

static int (*original_fstatat)(int dirfd, const char* pathname, struct stat* buf, int flags);
static int replaced_fstatat(int dirfd, const char* pathname, struct stat* buf, int flags) {
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "fstatat", ext);

    if(!ext) {
        return original_fstatat(dirfd, pathname, buf, flags);
    }

    if(shdw_at_path_denied(dirfd, pathname)) {
        return -1;
    }

    return original_fstatat(dirfd, pathname, buf, flags);
}

static int (*original_faccessat)(int dirfd, const char* pathname, int mode, int flags);
static int replaced_faccessat(int dirfd, const char* pathname, int mode, int flags) {
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "faccessat", ext);

    if(!ext) {
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
    if(!isCallerExternal()) {
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
                // Per-entry pool: @(d_name) and the restriction check
                // autorelease per entry; without it raw-pthread callers
                // (no pool) leak every skipped name.
                @autoreleasepool {
                    if([_shadow isPathRestricted:@((*oresult)->d_name) options:options]) {
                        // call readdir again to skip ahead
                        result = original_readdir_r(dirp, entry, oresult);
                    } else {
                        break;
                    }
                }
            } while(result == 0 && *oresult);

            CFRelease((__bridge CFDictionaryRef)options);
        }
    }

    return result;
}

static struct dirent* (*original_readdir)(DIR* dirp);
static struct dirent* replaced_readdir(DIR* dirp) {
    if(!isCallerExternal()) {
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
            // Per-entry pool: @(d_name) and the restriction check autorelease
            // per entry; without it raw-pthread callers (no pool) leak every
            // skipped name.
            @autoreleasepool {
                if([_shadow isPathRestricted:@(result->d_name) options:options]) {
                    // call readdir again to skip ahead
                    result = original_readdir(dirp);
                } else {
                    break;
                }
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
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "fopen", ext);

    if(!ext || ![_shadow isCPathRestricted:pathname]) {
        return original_fopen(pathname, mode);
    }

    errno = ENOENT;
    return NULL;
}

static FILE* (*original_freopen)(const char* pathname, const char* mode, FILE* stream);
static FILE* replaced_freopen(const char* pathname, const char* mode, FILE* stream) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_freopen(pathname, mode, stream);
    }

    errno = ENOENT;
    return NULL;
}

static char* (*original_realpath)(const char* pathname, char* resolved_path);
static char* replaced_realpath(const char* pathname, char* resolved_path) {
    char* result = original_realpath(pathname, resolved_path);

    if(result && isCallerExternal()) {
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
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(path, "getattrlist", ext);

    int result = original_getattrlist(path, attrList, attrBuf, attrBufSize, options);

    if(result != -1 && ext && [_shadow isCPathRestricted:path]) {
        errno = ENOENT;
        return -1;
    }

    return result;
}

// APFS snapshot enumeration: a detector can list jailbreak fakefs snapshots
// via fs_snapshot_list, so external callers get the jailbreak snapshot names
// compacted out of the returned buffer. No raw-syscall hook: there is no
// public SYS_fs_snapshot_list number in the SDK (only SYS_fs_snapshot 518),
// so raw-syscall users are vanishingly rare — libc-level hook only.
//
// Buffer format (device-tested reference: SystemRulesGenerator.m
// _findSnapshotNameWithFd): fs_snapshot_list(2) is getattrlistbulk(2) with
// FSOPT_LIST_SNAPSHOTS — the attrlist is passed IN (requesting
// ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME), NOT written at the buffer start.
// The buffer holds variable-length records: uint32 length, attribute_set_t
// returned attrs, then the name attrreference_t at
// 4 + sizeof(attribute_set_t) = 24. The return value is the NUMBER OF
// RECORDS (not a byte count); 0 = empty. The name string sits at
// buf + offset + kNameRefOffset + nameRef.attr_dataoffset, NUL-terminated
// within the record. shdw_snapshot_is_jb only exact-matches "fakefs", so
// stock "com.apple.os.update-*" names are inherently safe.
static int (*original_fs_snapshot_list)(int, struct attrlist*, void*, size_t, uint32_t);
static int replaced_fs_snapshot_list(int dirfd, struct attrlist* attrs, void* buf, size_t bufsize, uint32_t flags) {
    if(!isCallerExternal()) {
        return original_fs_snapshot_list(dirfd, attrs, buf, bufsize, flags);
    }

    int result = original_fs_snapshot_list(dirfd, attrs, buf, bufsize, flags);

    if(result > 0 && buf) {
        // Record layout (mirrors SystemRulesGenerator.m:245-249): uint32
        // length, attribute_set_t returned attrs, then the name
        // attrreference_t at 4 + sizeof(attribute_set_t) = 24.
        const uint32_t kNameRefOffset = (uint32_t)(sizeof(uint32_t) + sizeof(attribute_set_t));
        const uint32_t kMinRecord = kNameRefOffset + (uint32_t)sizeof(attrreference_t) + 1;

        uint32_t offset = 0;
        int valid = 1;

        // Pass 1 (validate): walk `result` records exactly like
        // SystemRulesGenerator.m:253-322. If ANY record is malformed, leave
        // the buffer completely unchanged and return the original result
        // (fail soft — a partially compacted buffer would corrupt the
        // caller's record walk).
        for(int record = 0; record < result; record++) {
            // The record header must fit in the buffer.
            if((uint64_t) offset + sizeof(uint32_t) > bufsize) {
                valid = 0;
                break;
            }

            uint32_t recLen;
            memcpy(&recLen, (char*) buf + offset, sizeof(recLen));

            // Minimum record: length + attribute_set_t + attrreference + NUL.
            if(recLen < kMinRecord || (uint64_t) offset + recLen > bufsize) {
                valid = 0;
                break;
            }

            // Trust the name reference only if the returned-attrs bitmap
            // says the name attribute was actually returned.
            attribute_set_t returned;
            memcpy(&returned, (char*) buf + offset + sizeof(uint32_t), sizeof(returned));

            if(!(returned.commonattr & ATTR_CMN_NAME)) {
                valid = 0;
                break;
            }

            // nameRef follows the length and attribute_set_t; its
            // attr_dataoffset is relative to the START of the attrreference.
            attrreference_t nameRef;
            memcpy(&nameRef, (char*) buf + offset + kNameRefOffset, sizeof(nameRef));

            if(nameRef.attr_dataoffset < (int32_t) sizeof(nameRef)) {
                valid = 0;
                break;
            }

            // The NUL-terminated name string must fit inside the record.
            uint32_t nameOffset = (uint32_t) nameRef.attr_dataoffset;

            if((uint64_t) nameOffset + 1 > (uint64_t) recLen - kNameRefOffset) {
                valid = 0;
                break;
            }

            const char* nameStr = (char*) buf + offset + kNameRefOffset + nameOffset;

            // Bound the scan by the record tail AND the kernel-reported
            // attribute length; the NUL must be found within the bound.
            size_t avail = recLen - kNameRefOffset - nameOffset;

            if(nameRef.attr_length < avail) {
                avail = nameRef.attr_length;
            }

            if(strnlen(nameStr, avail) == avail) {
                valid = 0;  // no NUL within the bounded name: malformed
                break;
            }

            offset += recLen;  // recLen >= kMinRecord: offset strictly advances
        }

        if(valid) {
            // Pass 2 (compact): for each valid record, extract the name and
            // if shdw_snapshot_is_jb(name) is 1, memmove the tail down by
            // recLen and decrement the record count. Survivors stay in place.
            size_t totalBytes = offset;  // byte extent of the records region
            offset = 0;

            for(int record = 0; record < result; record++) {
                uint32_t recLen;
                memcpy(&recLen, (char*) buf + offset, sizeof(recLen));

                attrreference_t nameRef;
                memcpy(&nameRef, (char*) buf + offset + kNameRefOffset, sizeof(nameRef));

                uint32_t nameOffset = (uint32_t) nameRef.attr_dataoffset;
                const char* nameStr = (char*) buf + offset + kNameRefOffset + nameOffset;

                if(shdw_snapshot_is_jb(nameStr)) {
                    // Remove: shift the tail down over this record; the next
                    // record now starts at the same offset.
                    memmove((char*) buf + offset, (char*) buf + offset + recLen, totalBytes - (offset + recLen));
                    totalBytes -= recLen;
                    result--;
                } else {
                    offset += recLen;
                }
            }
        }
    }

    return result;
}

static ssize_t (*original_getxattr)(const char* path, const char* name, void* value, size_t size, u_int32_t position, int options);
static ssize_t replaced_getxattr(const char* path, const char* name, void* value, size_t size, u_int32_t position, int options) {
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(path, "getxattr", ext);

    ssize_t result = original_getxattr(path, name, value, size, position, options);

    if(result != -1 && ext && [_shadow isCPathRestricted:path]) {
        errno = ENOENT;
        return -1;
    }

    return result;
}

static ssize_t (*original_listxattr)(const char* path, char* namebuf, size_t size, int options);
static ssize_t replaced_listxattr(const char* path, char* namebuf, size_t size, int options) {
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(path, "listxattr", ext);

    ssize_t result = original_listxattr(path, namebuf, size, options);

    if(result != -1 && ext && [_shadow isCPathRestricted:path]) {
        errno = ENOENT;
        return -1;
    }

    return result;
}

// fd-based xattr/getattrlist variants: resolve the descriptor's path via
// F_GETPATH and deny a restricted path with the same ENOENT the path-based
// siblings answer. A descriptor whose path can't be named passes through
// unfiltered (fail open — the fd may be a tty/pipe/socket with no path).
static ssize_t (*original_fgetxattr)(int fd, const char* name, void* value, size_t size, u_int32_t position, int options);
static ssize_t replaced_fgetxattr(int fd, const char* name, void* value, size_t size, u_int32_t position, int options) {
    if(!isCallerExternal()) {
        return original_fgetxattr(fd, name, value, size, position, options);
    }

    if(shdw_fd_path_restricted(fd)) {
        errno = ENOENT;
        return -1;
    }

    return original_fgetxattr(fd, name, value, size, position, options);
}

static ssize_t (*original_flistxattr)(int fd, char* namebuf, size_t size, int options);
static ssize_t replaced_flistxattr(int fd, char* namebuf, size_t size, int options) {
    if(!isCallerExternal()) {
        return original_flistxattr(fd, namebuf, size, options);
    }

    if(shdw_fd_path_restricted(fd)) {
        errno = ENOENT;
        return -1;
    }

    return original_flistxattr(fd, namebuf, size, options);
}

static int (*original_fgetattrlist)(int fd, struct attrlist* attrList, void* attrBuf, size_t attrBufSize, unsigned long options);
static int replaced_fgetattrlist(int fd, struct attrlist* attrList, void* attrBuf, size_t attrBufSize, unsigned long options) {
    if(!isCallerExternal()) {
        return original_fgetattrlist(fd, attrList, attrBuf, attrBufSize, options);
    }

    if(shdw_fd_path_restricted(fd)) {
        errno = ENOENT;
        return -1;
    }

    return original_fgetattrlist(fd, attrList, attrBuf, attrBufSize, options);
}

static int (*original_symlink)(const char* path1, const char* path2);
static int replaced_symlink(const char* path1, const char* path2) {
    if(!isCallerExternal()) {
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
    if(!isCallerExternal() || !([_shadow isCPathRestricted:path1] || [_shadow isCPathRestricted:path2])) {
        return original_link(path1, path2);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_rename)(const char* old, const char* new);
static int replaced_rename(const char* old, const char* new) {
    if(!isCallerExternal() || !([_shadow isCPathRestricted:old] || [_shadow isCPathRestricted:new])) {
        return original_rename(old, new);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_remove)(const char* pathname);
static int replaced_remove(const char* pathname) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_remove(pathname);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_unlink)(const char* pathname);
static int replaced_unlink(const char* pathname) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_unlink(pathname);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_unlinkat)(int dirfd, const char* pathname, int flags);
static int replaced_unlinkat(int dirfd, const char* pathname, int flags) {
    if(!isCallerExternal()) {
        return original_unlinkat(dirfd, pathname, flags);
    }

    if(shdw_at_path_denied(dirfd, pathname)) {
        return -1;
    }

    return original_unlinkat(dirfd, pathname, flags);
}

static int (*original_linkat)(int dirfd1, const char* path1, int dirfd2, const char* path2, int flags);
static int replaced_linkat(int dirfd1, const char* path1, int dirfd2, const char* path2, int flags) {
    if(!isCallerExternal()) {
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
    if(!isCallerExternal()) {
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
    if(!isCallerExternal()) {
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
    if(!isCallerExternal()) {
        return original_mkdirat(dirfd, path, mode);
    }

    if(shdw_at_path_denied(dirfd, path)) {
        return -1;
    }

    return original_mkdirat(dirfd, path, mode);
}

static int (*original_utimensat)(int dirfd, const char* path, const struct timespec times[2], int flags);
static int replaced_utimensat(int dirfd, const char* path, const struct timespec times[2], int flags) {
    if(!isCallerExternal()) {
        return original_utimensat(dirfd, path, times, flags);
    }

    if(shdw_at_path_denied(dirfd, path)) {
        return -1;
    }

    return original_utimensat(dirfd, path, times, flags);
}

static int (*original_fchmodat)(int dirfd, const char* path, mode_t mode, int flags);
static int replaced_fchmodat(int dirfd, const char* path, mode_t mode, int flags) {
    if(!isCallerExternal()) {
        return original_fchmodat(dirfd, path, mode, flags);
    }

    if(shdw_at_path_denied(dirfd, path)) {
        return -1;
    }

    return original_fchmodat(dirfd, path, mode, flags);
}

static int (*original_rmdir)(const char* pathname);
static int replaced_rmdir(const char* pathname) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_rmdir(pathname);
    }

    errno = ENOENT;
    return -1;
}

static long (*original_pathconf)(const char* pathname, int name);
static long replaced_pathconf(const char* pathname, int name) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_pathconf(pathname, name);
    }

    errno = ENOENT;
    return -1;
}

static long (*original_fpathconf)(int fd, int name);
static long replaced_fpathconf(int fd, int name) {
    if(!isCallerExternal()) {
        return original_fpathconf(fd, name);
    }
    
    if(shdw_fd_path_restricted(fd)) {
        errno = EBADF;
        return -1;
    }

    return original_fpathconf(fd, name);
}

static int (*original_utimes)(const char* pathname, const struct timeval times[2]);
static int replaced_utimes(const char* pathname, const struct timeval times[2]) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_utimes(pathname, times);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_futimes)(int fd, const struct timeval times[2]);
static int replaced_futimes(int fd, const struct timeval times[2]) {
    if(!isCallerExternal()) {
        return original_futimes(fd, times);
    }
    
    if(shdw_fd_path_restricted(fd)) {
        errno = EBADF;
        return -1;
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
    if(!isCallerExternal()) {
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

// libproc.h isn't shipped in the theos SDK; declare the symbols we need
// (all stable libSystem exports).
extern int proc_pidpath(int pid, void* buffer, uint32_t buffersize);
extern int proc_listpids(uint32_t type, uint32_t typeinfo, void* buffer, int buffersize);
extern int proc_listallpids(void* buffer, int buffersize);
extern int proc_pidinfo(int pid, int flavor, uint64_t arg, void* buffer, int buffersize);

// libproc.h isn't shipped in the theos SDK either, so declare the two pieces
// of the PROC_PIDTBSDINFO query we mask. proc_bsdinfo is a stable public ABI;
// the prefix layout matches it exactly (pbi_ppid at offset 0x10). Only that
// field is ever written.
#define SHADOW_PROC_PIDTBSDINFO 3

struct shdw_proc_bsdinfo_prefix {
    uint32_t pbi_flags;    /* 0x00 */
    uint32_t pbi_status;   /* 0x04 */
    uint32_t pbi_xstatus;  /* 0x08 */
    uint32_t pbi_pid;      /* 0x0c */
    uint32_t pbi_ppid;     /* 0x10 */
};

static int (*original_sysctl)(int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen);

// Classifies a process as restricted (jailbreak daemon) by its executable
// path. proc_pidpath is visible for other pids on iOS; when it fails (EPERM)
// the process can't be classified and is kept — denying legitimate processes
// would corrupt the process count on stock devices.
//
// Verdicts are cached keyed on pid + process start time (the same identity
// trick as shadowd's owner_dead, so a reused pid can't inherit a stale
// verdict), with a short TTL because a process can exec a different binary
// without changing its start time. Fixed-size table, round-robin eviction —
// a miss just re-classifies, results stay identical. The lock is never held
// across classification: isCPathRestricted is an ObjC call that could
// re-enter hooked code.
#define SHADW_PROC_CACHE_SIZE 32
#define SHADW_PROC_CACHE_TTL 5  // seconds

typedef struct {
    pid_t pid;
    time_t start_sec;        // kp_proc.p_starttime
    suseconds_t start_usec;
    time_t stamp;            // time(NULL) at fill
    BOOL restricted;
} shdw_proc_cache_entry_t;

static shdw_proc_cache_entry_t shdw_proc_cache[SHADW_PROC_CACHE_SIZE];
static NSUInteger shdw_proc_cache_next = 0;
static os_unfair_lock shdw_proc_cache_lock = OS_UNFAIR_LOCK_INIT;

static BOOL shdw_proc_is_restricted(const struct kinfo_proc* p) {
    pid_t pid = p->kp_proc.p_pid;
    time_t start_sec = p->kp_proc.p_starttime.tv_sec;
    suseconds_t start_usec = p->kp_proc.p_starttime.tv_usec;
    time_t now = time(NULL);

    os_unfair_lock_lock(&shdw_proc_cache_lock);

    for(NSUInteger i = 0; i < SHADW_PROC_CACHE_SIZE; i++) {
        const shdw_proc_cache_entry_t* e = &shdw_proc_cache[i];

        if(e->pid == pid
        && e->start_sec == start_sec
        && e->start_usec == start_usec
        && now - e->stamp < SHADW_PROC_CACHE_TTL) {
            BOOL verdict = e->restricted;
            os_unfair_lock_unlock(&shdw_proc_cache_lock);
            return verdict;
        }
    }

    os_unfair_lock_unlock(&shdw_proc_cache_lock);

    char path[PATH_MAX];
    BOOL restricted = NO;

    if(proc_pidpath(pid, path, sizeof(path)) > 0) {
        restricted = [_shadow isCPathRestricted:path];
    }

    os_unfair_lock_lock(&shdw_proc_cache_lock);

    NSUInteger slot = shdw_proc_cache_next;
    shdw_proc_cache_next = (shdw_proc_cache_next + 1) % SHADW_PROC_CACHE_SIZE;

    shdw_proc_cache[slot].pid = pid;
    shdw_proc_cache[slot].start_sec = start_sec;
    shdw_proc_cache[slot].start_usec = start_usec;
    shdw_proc_cache[slot].stamp = now;
    shdw_proc_cache[slot].restricted = restricted;

    os_unfair_lock_unlock(&shdw_proc_cache_lock);
    return restricted;
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

            // Cross-API consistency: getppid() reports parent 1, so the
            // own record must say the same (see replaced_sysctl).
            p->kp_eproc.e_ppid = 1;
        } else if(shdw_proc_is_restricted(p)) {
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

// KERN_PROCARGS2 payload filter (self pid): the kernel payload encodes
// [int argc][char* argv[argc+1]][char* envp...][strings blob], argv/envp
// pointers referencing the strings blob. The kernel view carries the
// launch-time injection flags and the unfiltered environment while
// -[NSProcessInfo arguments] / getenv() / _NSGetEnviron() report the
// filtered view — a detector comparing the two channels sees the
// contradiction. When the views differ, the payload is rebuilt in place with
// the SAME drop rules as those hooks: injection flags (with their value),
// restricted paths, DYLD_*/JAILBREAKD_*/safe-mode env entries and jailbreak
// PATH components. The strings blob is memmoved down, every kept pointer
// into it is shifted by the compaction amount, and a sanitized PATH= entry
// is prefixed to the blob when it changed. Malformed payloads pass through
// untouched.
void shdw_procargs2_filter(void* oldp, size_t* oldlenp) {
    @autoreleasepool {
        if(!oldp || !oldlenp) {
            return;
        }

        size_t len = *oldlenp;
        char* base = (char *) oldp;

        if(len < sizeof(int) + sizeof(char *)) {
            return;
        }

        int argc = ((int *) base)[0];
        char** argv = (char **) (base + sizeof(int));

        if(argc <= 0) {
            return;
        }

        size_t argv_slots = (size_t) argc + 1;

        if(sizeof(int) + argv_slots * sizeof(char *) + sizeof(char *) > len) {
            return;  // no room for the envp terminator: malformed
        }

        char** envp = argv + argv_slots;
        size_t envp_count = 0;
        size_t max_env = (len - (sizeof(int) + argv_slots * sizeof(char *))) / sizeof(char *);

        while(envp_count < max_env && envp[envp_count] != NULL) {
            envp_count++;
        }

        if(envp_count == max_env) {
            return;  // envp terminator missing from the payload: malformed
        }

        char* blob_start = (char *) envp + (envp_count + 1) * sizeof(char *);
        char* blob_end = base + len;

        // ---- argv drop decisions (mirrors -[NSProcessInfo arguments]) ----
        BOOL* keep = (BOOL *) calloc((size_t) argc, sizeof(BOOL));

        if(!keep) {
            return;
        }

        int new_argc = 0;

        for(int i = 0; i < argc; i++) {
            char* a = argv[i];

            if(a == NULL || a < blob_start || a >= blob_end) {
                keep[i] = YES;  // NULL or unclassifiable: keep
                new_argc++;
                continue;
            }

            if([_shadow isCPathRestricted:a]) {
                continue;  // restricted path argument: drop
            }

            if(strcmp(a, "-dylib") == 0 || strcmp(a, "-insert") == 0 || strcmp(a, "-load") == 0
            || strcmp(a, "-bundle") == 0 || strcmp(a, "-init") == 0) {
                if(i + 1 < argc) {
                    i++;  // drop the flag's value slot as well
                }

                continue;
            }

            keep[i] = YES;
            new_argc++;
        }

        // ---- env entries (mirrors getenv/_NSGetEnviron) ----
        char** env_keep = (char **) malloc((envp_count + 1) * sizeof(char *));

        if(!env_keep) {
            free(keep);
            return;
        }

        size_t eout = 0;
        char* sanitized_path = NULL;
        char* path_blob_ptr = NULL;  // blob pointer of the (single) PATH entry
        static _Thread_local char* path_entry_storage = NULL;
        static _Thread_local size_t path_entry_capacity = 0;

        for(size_t i = 0; i < envp_count; i++) {
            char* e = envp[i];

            if(e == NULL || e < blob_start || e >= blob_end) {
                continue;
            }

            if(strncmp(e, "DYLD_", 5) == 0 || strncmp(e, "JAILBREAKD_", 11) == 0) {
                continue;
            }

            if(strncmp(e, "_MSSafeMode=", 12) == 0 || strncmp(e, "_SafeMode=", 10) == 0
            || strncmp(e, "_SubstituteSafeMode=", 20) == 0) {
                continue;
            }

            if(strncmp(e, "PATH=", 5) == 0 && e[5]) {
                // Rewrite the PATH entry in place (same sanitizer shape as the
                // getenv PATH hook). The sanitized value is always SHORTER
                // than the original, so it fits where the original string
                // lives inside the blob — no payload growth, pointer stays at
                // its (shifted) blob location.
                NSArray* parts = [[NSString stringWithUTF8String:e + 5] componentsSeparatedByString:@":"];
                NSMutableArray* kept = [NSMutableArray arrayWithCapacity:parts.count];

                for(NSString* part in parts) {
                    if([part hasPrefix:@"/var/jb"]
                    || [part hasPrefix:@"/private/preboot"]
                    || [part hasPrefix:@"/preboot"]) {
                        continue;
                    }

                    [kept addObject:part];
                }

                if(kept.count != parts.count) {
                    NSString* joined = [NSString stringWithFormat:@"PATH=%@", [kept componentsJoinedByString:@":"]];
                    size_t nlen = [joined lengthOfBytesUsingEncoding:NSUTF8StringEncoding] + 1;

                    if(nlen > path_entry_capacity) {
                        char* grown = realloc(path_entry_storage, nlen);

                        if(grown) {
                            path_entry_storage = grown;
                            path_entry_capacity = nlen;
                        }
                    }

                    if(path_entry_storage && path_entry_capacity >= nlen) {
                        strcpy(path_entry_storage, joined.UTF8String);
                        sanitized_path = path_entry_storage;
                        path_blob_ptr = e;
                    }
                }

                env_keep[eout++] = e;
                continue;
            }

            env_keep[eout++] = e;
        }

        size_t new_envp_count = eout;

        // ---- rebuild geometry ----
        size_t new_arrays_end = sizeof(int) + ((size_t) new_argc + 1 + new_envp_count + 1) * sizeof(char *);
        size_t old_blob_off = sizeof(int) + (argv_slots + envp_count + 1) * sizeof(char *);

        if(new_arrays_end > old_blob_off) {
            // Arrays only shrink when dropping entries; never grow the payload.
            free(keep);
            free(env_keep);
            return;
        }

        ptrdiff_t shift = (ptrdiff_t)(old_blob_off - new_arrays_end);

        if(shift == 0 && !sanitized_path) {
            free(keep);
            free(env_keep);
            return;  // the payload already agrees with the filtered view
        }

        // ---- write back (all reads below are from captured state) ----
        ((int *) base)[0] = new_argc;

        char** dst = argv;

        for(int i = 0; i < argc; i++) {
            if(keep[i]) {
                *dst++ = argv[i] ? argv[i] - shift : NULL;
            }
        }

        *dst = NULL;
        dst++;

        for(size_t i = 0; i < new_envp_count; i++) {
            *dst++ = env_keep[i] - shift;  // all entries live in the blob
        }

        *dst = NULL;

        if(shift > 0) {
            memmove(base + new_arrays_end, base + old_blob_off, len - old_blob_off);
        }

        if(sanitized_path && path_blob_ptr) {
            // Rewrite the PATH entry in its (moved) blob location. The value
            // is shorter than the original that occupied this space, so the
            // write stays inside the payload.
            strcpy(path_blob_ptr - shift, sanitized_path);
        }

        *oldlenp = new_arrays_end + (len - old_blob_off);

        free(keep);
        free(env_keep);
    }
}

// KERN_PROC/PROCARGS2 per-pid and proc-list filtering (defined further down;
// forward-declared so the sysctl hook below can call it).
static BOOL shdw_libproc_pid_is_restricted(pid_t pid);

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

    // Per-pid queries of a jailbreak daemon must answer ENOENT, the same
    // hiding the KERN_PROC_ALL filter applies to the list (a pid-scanning
    // detector steps the MIB pid by pid).
    BOOL isOtherPid = name[0] == CTL_KERN
        && namelen == 4
        && name[1] == KERN_PROC
        && name[2] == KERN_PROC_PID
        && name[3] > 0
        && name[3] != getpid();

    // KERN_PROCARGS2 is a direct CTL_KERN child: {CTL_KERN, KERN_PROCARGS2, pid}.
    BOOL isOwnProcargs = name[0] == CTL_KERN
        && namelen == 3
        && name[1] == KERN_PROCARGS2
        && name[2] == getpid();

    BOOL isOtherProcargs = name[0] == CTL_KERN
        && namelen == 3
        && name[1] == KERN_PROCARGS2
        && name[2] > 0
        && name[2] != getpid();

    if(isOtherPid || isOtherProcargs) {
        pid_t other = isOtherPid ? name[3] : name[2];

        if(shdw_libproc_pid_is_restricted(other)) {
            errno = ENOENT;
            return -1;
        }
    }

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

        // Cross-API consistency: getppid() reports parent 1, so the own
        // record must say the same — a detector comparing getppid() against
        // kp_eproc.e_ppid would otherwise see the real parent (debugger, host app).
        p->kp_eproc.e_ppid = 1;
    }

    // Own KERN_PROCARGS2: the kernel payload is the raw launch argv/envp;
    // rebuild it to agree with the filtered NSProcessInfo/getenv views.
    if(ret == 0 && isOwnProcargs && oldp && oldlenp && *oldlenp > (size_t) sizeof(int)) {
        shdw_procargs2_filter(oldp, oldlenp);
    }

    return ret;
}

static pid_t (*original_getppid)(void);
static pid_t replaced_getppid(void) {
    if(!isCallerExternal()) {
        // Shadow-internal callers get the real parent; the app/detector
        // sees the stock answer for a process without a debugger parent.
        return original_getppid();
    }

    return 1;
}

// getrusage(RUSAGE_CHILDREN): a detector spawns a child to test execution
// and measures its CPU usage to infer a jailbreak. Zero the child-accounting
// fields for external callers so the probe sees a child that never ran.
// RUSAGE_SELF is untouched — it is the caller's own accounting and carries
// no jailbreak signal.
static int (*original_getrusage)(int who, struct rusage* usage);
static int replaced_getrusage(int who, struct rusage* usage) {
    int result = original_getrusage(who, usage);

    if(result == 0 && isCallerExternal() && who == RUSAGE_CHILDREN && usage) {
        memset(usage, 0, sizeof(*usage));
    }

    return result;
}

// getrlimit: pass-through (conservative). RLIMIT probes are not a reliable
// jailbreak signal — legitimate apps set/read limits routinely — so no
// fabrication here; the hook exists for coverage and to keep the symbol in
// the dlsym policy table (GOT-vs-dlsym agreement).
static int (*original_getrlimit)(int resource, struct rlimit* rlp);
static int replaced_getrlimit(int resource, struct rlimit* rlp) {
    return original_getrlimit(resource, rlp);
}

// libproc enumeration (proc_listpids/proc_listallpids/proc_pidinfo) is the
// second process-list surface after sysctl KERN_PROC: detectors enumerate
// pids and query per-pid details to find jailbreak daemons. The sysctl hook
// filters the kinfo_proc list; these hooks filter the libproc views of the
// same processes. Classification is pid-only (libproc hands us no start
// time), so the cache keys on pid alone with a short TTL — a reused pid can
// inherit a stale verdict for at most TTL seconds, and a miss just
// re-classifies, so results stay identical. Same fail-open rule as the
// sysctl path: an unclassifiable process (proc_pidpath EPERM) is kept —
// denying legitimate processes would corrupt process counts on stock
// devices. The lock is never held across classification (isCPathRestricted
// is an ObjC call that could re-enter hooked code).
#define SHADW_LIBPROC_CACHE_SIZE 32
#define SHADW_LIBPROC_CACHE_TTL 5  // seconds

typedef struct {
    pid_t pid;
    time_t stamp;
    BOOL restricted;
} shdw_libproc_cache_entry_t;

static shdw_libproc_cache_entry_t shdw_libproc_cache[SHADW_LIBPROC_CACHE_SIZE];
static NSUInteger shdw_libproc_cache_next = 0;
static os_unfair_lock shdw_libproc_cache_lock = OS_UNFAIR_LOCK_INIT;

static BOOL shdw_libproc_pid_is_restricted(pid_t pid) {
    time_t now = time(NULL);

    os_unfair_lock_lock(&shdw_libproc_cache_lock);

    for(NSUInteger i = 0; i < SHADW_LIBPROC_CACHE_SIZE; i++) {
        const shdw_libproc_cache_entry_t* e = &shdw_libproc_cache[i];

        if(e->pid == pid && now - e->stamp < SHADW_LIBPROC_CACHE_TTL) {
            BOOL verdict = e->restricted;
            os_unfair_lock_unlock(&shdw_libproc_cache_lock);
            return verdict;
        }
    }

    os_unfair_lock_unlock(&shdw_libproc_cache_lock);

    char path[PATH_MAX];
    BOOL restricted = NO;

    if(proc_pidpath(pid, path, sizeof(path)) > 0) {
        restricted = [_shadow isCPathRestricted:path];
    }

    os_unfair_lock_lock(&shdw_libproc_cache_lock);

    NSUInteger slot = shdw_libproc_cache_next;
    shdw_libproc_cache_next = (shdw_libproc_cache_next + 1) % SHADW_LIBPROC_CACHE_SIZE;

    shdw_libproc_cache[slot].pid = pid;
    shdw_libproc_cache[slot].stamp = now;
    shdw_libproc_cache[slot].restricted = restricted;

    os_unfair_lock_unlock(&shdw_libproc_cache_lock);
    return restricted;
}

// Compacts restricted pids out of a proc_listpids/proc_listallpids result
// buffer in place. The buffer holds pid_t entries; the return value is the
// pid count. Returns the filtered count (0 when everything was removed —
// the caller reads that as "no processes", the same hiding the sysctl
// filter achieves).
static int shdw_libproc_pids_filtered(pid_t* pids, int count) {
    int out = 0;

    for(int i = 0; i < count; i++) {
        if(shdw_libproc_pid_is_restricted(pids[i])) {
            continue;  // jailbreak daemon: removed from the list
        }

        if(out != i) {
            pids[out] = pids[i];
        }

        out++;
    }

    return out;
}

static int (*original_proc_listpids)(uint32_t type, uint32_t typeinfo, void* buffer, int buffersize);
static int replaced_proc_listpids(uint32_t type, uint32_t typeinfo, void* buffer, int buffersize) {
    int count = original_proc_listpids(type, typeinfo, buffer, buffersize);

    if(count <= 0 || !buffer || !isCallerExternal()) {
        return count;
    }

    return shdw_libproc_pids_filtered((pid_t*) buffer, count);
}

static int (*original_proc_listallpids)(void* buffer, int buffersize);
static int replaced_proc_listallpids(void* buffer, int buffersize) {
    int count = original_proc_listallpids(buffer, buffersize);

    if(count <= 0 || !buffer || !isCallerExternal()) {
        return count;
    }

    return shdw_libproc_pids_filtered((pid_t*) buffer, count);
}

static int (*original_proc_pidinfo)(int pid, int flavor, uint64_t arg, void* buffer, int buffersize);
static int replaced_proc_pidinfo(int pid, int flavor, uint64_t arg, void* buffer, int buffersize) {
    if(isCallerExternal() && shdw_libproc_pid_is_restricted(pid)) {
        // Jailbreak daemon: deny the per-pid query the same way the pid
        // list filters deny enumeration. EPERM matches what an unprivileged
        // caller sees for processes it may not inspect.
        errno = EPERM;
        return 0;
    }

    int ret = original_proc_pidinfo(pid, flavor, arg, buffer, buffersize);

    // Cross-API consistency: getppid() reports parent 1, so the own
    // process's BSD info must say the same — a detector comparing
    // getppid() against pbi_ppid would otherwise see the real parent.
    if(ret > 0 && isCallerExternal() && pid == getpid() && flavor == SHADOW_PROC_PIDTBSDINFO
    && buffer && buffersize >= sizeof(struct shdw_proc_bsdinfo_prefix)) {
        ((struct shdw_proc_bsdinfo_prefix*) buffer)->pbi_ppid = 1;
    }

    return ret;
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

    // C fast-path: the probe matches a path COMPONENT equal to ".jbroot";
    // if the string doesn't contain it at all, no NSString work is needed.
    if(!strstr(pathname, ".jbroot")) {
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
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "open", ext);

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

    if(ext && shdw_is_jbroot_write_probe(pathname, oflag)) {
        // Stock fails with ENOENT since .jbroot doesn't exist there; must match
        // exactly so the probe can't distinguish us via a different errno.
        errno = ENOENT;
        return -1;
    }

    if(!ext || ![_shadow isCPathRestricted:pathname]) {
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
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "openat", ext);

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

    if(!ext) {
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
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
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
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "stat64", ext);

    int result = original_stat64(pathname, buf);

    if(result != -1 && ext && [_shadow isCPathRestricted:pathname]) {
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
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "lstat64", ext);

    if(!ext) {
        return original_lstat64(pathname, buf);
    }

    // NULL caller buffer keeps stock semantics (EFAULT from the kernel);
    // replay before classification.
    if(buf == NULL) {
        return original_lstat64(pathname, NULL);
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

        // Only copy on success: on failure _buf is uninitialized stack.
        memcpy(buf, &_buf, sizeof(shdw_stat64_t));
    }

    return result;
}

static int (*original_fstat64)(int fd, shdw_stat64_t* buf);
static int replaced_fstat64(int fd, shdw_stat64_t* buf) {
    if(!isCallerExternal()) {
        return original_fstat64(fd, buf);
    }

    if(shdw_fd_path_restricted(fd)) {
        errno = EBADF;
        return -1;
    }

    return original_fstat64(fd, buf);
}

static int (*original_fstatat64)(int dirfd, const char* pathname, shdw_stat64_t* buf, int flags);
static int replaced_fstatat64(int dirfd, const char* pathname, shdw_stat64_t* buf, int flags) {
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "fstatat64", ext);

    if(!ext) {
        return original_fstatat64(dirfd, pathname, buf, flags);
    }

    if(shdw_at_path_denied(dirfd, pathname)) {
        return -1;
    }

    return original_fstatat64(dirfd, pathname, buf, flags);
}

static int (*original_open_dprotected_np)(const char* path, int flags, int class, int dpflags, ...);
static int replaced_open_dprotected_np(const char* path, int flags, int class, int dpflags, ...) {
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(path, "open_dprotected_np", ext);

    mode_t mode = 0;

    // Same vararg rule as open: the mode argument exists only with O_CREAT.
    if(flags & O_CREAT) {
        va_list args;
        va_start(args, dpflags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }

    if(ext && shdw_is_jbroot_write_probe(path, flags)) {
        errno = ENOENT;
        return -1;
    }

    if(!ext || ![_shadow isCPathRestricted:path]) {
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
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(path, "openat_dprotected_np", ext);

    mode_t mode = 0;

    if(flags & O_CREAT) {
        va_list args;
        va_start(args, dpflags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }

    if(!ext) {
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
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(path, "openat_authenticated_np", ext);

    mode_t mode = 0;

    if(flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }

    if(!ext) {
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
    [hooks hookFunction:fs_snapshot_list withReplacement:replaced_fs_snapshot_list outOldPtr:(void **) &original_fs_snapshot_list];
    [hooks hookFunction:getxattr withReplacement:replaced_getxattr outOldPtr:(void **) &original_getxattr];
    [hooks hookFunction:listxattr withReplacement:replaced_listxattr outOldPtr:(void **) &original_listxattr];
    [hooks hookFunction:fgetxattr withReplacement:replaced_fgetxattr outOldPtr:(void **) &original_fgetxattr];
    [hooks hookFunction:flistxattr withReplacement:replaced_flistxattr outOldPtr:(void **) &original_flistxattr];
    [hooks hookFunction:fgetattrlist withReplacement:replaced_fgetattrlist outOldPtr:(void **) &original_fgetattrlist];
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

    if(!shdw_close_hooked) {
        [hooks hookFunction:close withReplacement:replaced_close outOldPtr:(void **) &original_close];
        shdw_close_hooked = YES;
    }
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

    if(!shdw_close_hooked) {
        [hooks hookFunction:close withReplacement:replaced_close outOldPtr:(void **) &original_close];
        shdw_close_hooked = YES;
    }
}

void shadowhook_libc_antidebugging(HKSubstitutor* hooks) {
    [hooks hookFunction:ptrace withReplacement:replaced_ptrace outOldPtr:(void **) &original_ptrace];
    [hooks hookFunction:sysctl withReplacement:replaced_sysctl outOldPtr:(void **) &original_sysctl];
    [hooks hookFunction:getppid withReplacement:replaced_getppid outOldPtr:(void **) &original_getppid];
    [hooks hookFunction:getrusage withReplacement:replaced_getrusage outOldPtr:(void **) &original_getrusage];
    [hooks hookFunction:getrlimit withReplacement:replaced_getrlimit outOldPtr:(void **) &original_getrlimit];

    // libproc enumeration: stable libSystem exports, resolved at runtime and
    // skipped cleanly when absent (same pattern as getmntinfo_r_np above).
    struct { const char* name; void* replacement; void** outOld; } shdw_libproc_symbols[] = {
        { "proc_listpids",    (void*) replaced_proc_listpids,    (void**) &original_proc_listpids },
        { "proc_listallpids", (void*) replaced_proc_listallpids, (void**) &original_proc_listallpids },
        { "proc_pidinfo",     (void*) replaced_proc_pidinfo,     (void**) &original_proc_pidinfo },
    };

    for(size_t i = 0; i < sizeof(shdw_libproc_symbols) / sizeof(shdw_libproc_symbols[0]); i++) {
        void* target = dlsym(RTLD_DEFAULT, shdw_libproc_symbols[i].name);

        if(target) {
            [hooks hookFunction:target withReplacement:shdw_libproc_symbols[i].replacement outOldPtr:shdw_libproc_symbols[i].outOld];
        }
    }
}

// Post-install verification: a hook that failed to install (backend error,
// symbol unresolvable) leaves its original_* NULL and the restriction
// silently unenforced. The ctor calls these after executeHooks for the groups
// it installed; each logs any NULL among the group's required symbols so a
// failed install surfaces instead of being invisible. Runtime-resolved
// optional symbols (stat64 family, protected-open variants, getmntinfo_r_np)
// and the iOS-11-gated utimensat are excluded — NULL there is expected.
// (shdw_hook_check_t / shdw_verify_hooks live in hooks.h.)
void shadowhook_libc_verify(void) {
    shdw_hook_check_t checks[] = {
        { "access", original_access }, { "chdir", original_chdir },
        { "chroot", original_chroot }, { "creat", original_creat },
        { "statfs", original_statfs }, { "fstatfs", original_fstatfs },
        { "statvfs", original_statvfs }, { "fstatvfs", original_fstatvfs },
        { "stat", original_stat }, { "lstat", original_lstat },
        { "faccessat", original_faccessat }, { "readdir_r", original_readdir_r },
        { "readdir", original_readdir }, { "closedir", original_closedir },
        { "fopen", original_fopen }, { "freopen", original_freopen },
        { "realpath", original_realpath }, { "readlink", original_readlink },
        { "readlinkat", original_readlinkat }, { "link", original_link },
        { "getmntinfo", original_getmntinfo }, { "getattrlist", original_getattrlist },
        { "fs_snapshot_list", original_fs_snapshot_list },
        { "getxattr", original_getxattr }, { "listxattr", original_listxattr },
        { "fgetxattr", original_fgetxattr }, { "flistxattr", original_flistxattr },
        { "fgetattrlist", original_fgetattrlist }, { "symlink", original_symlink },
        { "rename", original_rename }, { "remove", original_remove },
        { "unlink", original_unlink }, { "unlinkat", original_unlinkat },
        { "linkat", original_linkat }, { "symlinkat", original_symlinkat },
        { "renameat", original_renameat }, { "mkdirat", original_mkdirat },
        { "fchmodat", original_fchmodat }, { "rmdir", original_rmdir },
        { "pathconf", original_pathconf }, { "fpathconf", original_fpathconf },
        { "utimes", original_utimes }, { "futimes", original_futimes },
        { "fchdir", original_fchdir }, { "getfsstat", original_getfsstat },
        { "fstat", original_fstat }, { "fstatat", original_fstatat },
    };

    shdw_verify_hooks("libc", checks, sizeof(checks) / sizeof(checks[0]));
}

void shadowhook_libc_envvar_verify(void) {
    shdw_hook_check_t checks[] = {
        { "getenv", original_getenv },
    };

    shdw_verify_hooks("libc_envvar", checks, sizeof(checks) / sizeof(checks[0]));
}

void shadowhook_libc_lowlevel_verify(void) {
    shdw_hook_check_t checks[] = {
        { "open", original_open }, { "openat", original_openat },
        { "__opendir2", original___opendir2 }, { "close", original_close },
    };

    shdw_verify_hooks("libc_lowlevel", checks, sizeof(checks) / sizeof(checks[0]));
}

void shadowhook_libc_antidebugging_verify(void) {
    // proc_listpids/proc_listallpids/proc_pidinfo are runtime-resolved:
    // excluded (NULL is expected when absent).
    shdw_hook_check_t checks[] = {
        { "ptrace", original_ptrace }, { "sysctl", original_sysctl },
        { "getppid", original_getppid }, { "getrusage", original_getrusage },
        { "getrlimit", original_getrlimit },
    };

    shdw_verify_hooks("libc_antidebugging", checks, sizeof(checks) / sizeof(checks[0]));
}

// Symbol policy for the libc C-function groups (see dyld.x's
// shdw_sym_policy_table): dlsym must resolve every fishhook-rebound libc
// export to its replacement for external callers, so the GOT-vs-dlsym
// comparison agrees. Guarded by the original pointer: a symbol only resolves
// to its replacement when the hook actually installed (original != NULL), so
// runtime-conditional symbols (stat64 family, libproc, getmntinfo_r_np) that
// are absent on a given OS stay absent.
typedef struct {
    const char* name;
    void* replacement;
    void* const* original;
} shdw_libc_sym_policy_entry_t;

static const shdw_libc_sym_policy_entry_t shdw_libc_sym_policy_table[] = {
    { "access", (void*)&replaced_access, (void* const*)&original_access },
    { "chdir", (void*)&replaced_chdir, (void* const*)&original_chdir },
    { "chroot", (void*)&replaced_chroot, (void* const*)&original_chroot },
    { "close", (void*)&replaced_close, (void* const*)&original_close },
    { "closedir", (void*)&replaced_closedir, (void* const*)&original_closedir },
    { "creat", (void*)&replaced_creat, (void* const*)&original_creat },
    { "faccessat", (void*)&replaced_faccessat, (void* const*)&original_faccessat },
    { "fchdir", (void*)&replaced_fchdir, (void* const*)&original_fchdir },
    { "fchmodat", (void*)&replaced_fchmodat, (void* const*)&original_fchmodat },
    { "fgetattrlist", (void*)&replaced_fgetattrlist, (void* const*)&original_fgetattrlist },
    { "fgetxattr", (void*)&replaced_fgetxattr, (void* const*)&original_fgetxattr },
    { "flistxattr", (void*)&replaced_flistxattr, (void* const*)&original_flistxattr },
    { "fopen", (void*)&replaced_fopen, (void* const*)&original_fopen },
    { "fpathconf", (void*)&replaced_fpathconf, (void* const*)&original_fpathconf },
    { "freopen", (void*)&replaced_freopen, (void* const*)&original_freopen },
    { "fstat", (void*)&replaced_fstat, (void* const*)&original_fstat },
    { "fstatat", (void*)&replaced_fstatat, (void* const*)&original_fstatat },
    { "fstatfs", (void*)&replaced_fstatfs, (void* const*)&original_fstatfs },
    { "fstatvfs", (void*)&replaced_fstatvfs, (void* const*)&original_fstatvfs },
    { "futimes", (void*)&replaced_futimes, (void* const*)&original_futimes },
    { "getattrlist", (void*)&replaced_getattrlist, (void* const*)&original_getattrlist },
    { "fs_snapshot_list", (void*)&replaced_fs_snapshot_list, (void* const*)&original_fs_snapshot_list },
    { "getenv", (void*)&replaced_getenv, (void* const*)&original_getenv },
    { "getfsstat", (void*)&replaced_getfsstat, (void* const*)&original_getfsstat },
    { "getmntinfo", (void*)&replaced_getmntinfo, (void* const*)&original_getmntinfo },
    { "getmntinfo_r_np", (void*)&shdw_replaced_getmntinfo_r_np, (void* const*)&original_getmntinfo_r_np },
    { "getppid", (void*)&replaced_getppid, (void* const*)&original_getppid },
    { "getrlimit", (void*)&replaced_getrlimit, (void* const*)&original_getrlimit },
    { "getrusage", (void*)&replaced_getrusage, (void* const*)&original_getrusage },
    { "getxattr", (void*)&replaced_getxattr, (void* const*)&original_getxattr },
    { "link", (void*)&replaced_link, (void* const*)&original_link },
    { "linkat", (void*)&replaced_linkat, (void* const*)&original_linkat },
    { "listxattr", (void*)&replaced_listxattr, (void* const*)&original_listxattr },
    { "lstat", (void*)&replaced_lstat, (void* const*)&original_lstat },
    { "mkdirat", (void*)&replaced_mkdirat, (void* const*)&original_mkdirat },
    { "open", (void*)&replaced_open, (void* const*)&original_open },
    { "openat", (void*)&replaced_openat, (void* const*)&original_openat },
    { "pathconf", (void*)&replaced_pathconf, (void* const*)&original_pathconf },
    { "proc_listallpids", (void*)&replaced_proc_listallpids, (void* const*)&original_proc_listallpids },
    { "proc_listpids", (void*)&replaced_proc_listpids, (void* const*)&original_proc_listpids },
    { "proc_pidinfo", (void*)&replaced_proc_pidinfo, (void* const*)&original_proc_pidinfo },
    { "ptrace", (void*)&replaced_ptrace, (void* const*)&original_ptrace },
    { "readdir", (void*)&replaced_readdir, (void* const*)&original_readdir },
    { "readdir_r", (void*)&replaced_readdir_r, (void* const*)&original_readdir_r },
    { "readlink", (void*)&replaced_readlink, (void* const*)&original_readlink },
    { "readlinkat", (void*)&replaced_readlinkat, (void* const*)&original_readlinkat },
    { "realpath", (void*)&replaced_realpath, (void* const*)&original_realpath },
    { "remove", (void*)&replaced_remove, (void* const*)&original_remove },
    { "rename", (void*)&replaced_rename, (void* const*)&original_rename },
    { "renameat", (void*)&replaced_renameat, (void* const*)&original_renameat },
    { "rmdir", (void*)&replaced_rmdir, (void* const*)&original_rmdir },
    { "stat", (void*)&replaced_stat, (void* const*)&original_stat },
    { "statfs", (void*)&replaced_statfs, (void* const*)&original_statfs },
    { "statvfs", (void*)&replaced_statvfs, (void* const*)&original_statvfs },
    { "symlink", (void*)&replaced_symlink, (void* const*)&original_symlink },
    { "symlinkat", (void*)&replaced_symlinkat, (void* const*)&original_symlinkat },
    { "sysctl", (void*)&replaced_sysctl, (void* const*)&original_sysctl },
    { "unlink", (void*)&replaced_unlink, (void* const*)&original_unlink },
    { "unlinkat", (void*)&replaced_unlinkat, (void* const*)&original_unlinkat },
    { "utimensat", (void*)&replaced_utimensat, (void* const*)&original_utimensat },
    { "utimes", (void*)&replaced_utimes, (void* const*)&original_utimes },
    { "__opendir2", (void*)&replaced___opendir2, (void* const*)&original___opendir2 },
    { "stat64", (void*)&replaced_stat64, (void* const*)&original_stat64 },
    { "lstat64", (void*)&replaced_lstat64, (void* const*)&original_lstat64 },
    { "fstat64", (void*)&replaced_fstat64, (void* const*)&original_fstat64 },
    { "fstatat64", (void*)&replaced_fstatat64, (void* const*)&original_fstatat64 },
    { "open_dprotected_np", (void*)&replaced_open_dprotected_np, (void* const*)&original_open_dprotected_np },
    { "openat_dprotected_np", (void*)&replaced_openat_dprotected_np, (void* const*)&original_openat_dprotected_np },
    { "openat_authenticated_np", (void*)&replaced_openat_authenticated_np, (void* const*)&original_openat_authenticated_np },
};

void* shdw_sym_policy_lookup_libc(const char* name) {
    if(!name) {
        return NULL;
    }

    for(size_t i = 0; i < sizeof(shdw_libc_sym_policy_table) / sizeof(shdw_libc_sym_policy_table[0]); i++) {
        if(strcmp(name, shdw_libc_sym_policy_table[i].name) == 0) {
            if(shdw_libc_sym_policy_table[i].original && *shdw_libc_sym_policy_table[i].original == NULL) {
                return NULL;  // runtime-conditional symbol not installed
            }

            return shdw_libc_sym_policy_table[i].replacement;
        }
    }

    return NULL;
}
