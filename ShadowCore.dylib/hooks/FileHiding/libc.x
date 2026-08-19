#import "hooks.h"
#import "filters.h"
#import "../../policy/EnvironmentPolicy.h"
#import "../../policy/PathPolicy.h"
#import "../../policy/ProcessPolicy.h"

#import <string.h>
#import <stdlib.h>
#import <sys/xattr.h>
#import <sys/resource.h>
#import <sys/attr.h>
#import <sys/snapshot.h>

static int (*original_access)(const char* pathname, int mode);
static int replaced_access(const char* pathname, int mode) {
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "access", ext);

    if(ext && [_shadow isCPathRestricted:pathname] && shdw_libc_try_rewrite(pathname)) {
        return original_access(pathname, mode);   // natural ENOENT
    }

    int result = original_access(pathname, mode);

    // Restricted-root paths (e.g. /var/jb) are always jailbreak indicators —
    // deny unconditionally. Other restricted paths respect the external-caller
    // gate so Shadow's own code can still access them when needed.
    if(result != -1) {
        BOOL restricted = [_shadow isCPathRestricted:pathname];
        if(restricted && (shdw_is_restricted_root(pathname) || ext)) {
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

static ssize_t (*original_readlink)(const char* pathname, char* buf, size_t bufsize);
static ssize_t replaced_readlink(const char* pathname, char* buf, size_t bufsize) {
    if(!isCallerExternal()) {
        return original_readlink(pathname, buf, bufsize);
    }

    if([_shadow isCPathRestricted:pathname] && shdw_libc_try_rewrite(pathname)) {
        return original_readlink(pathname, buf, bufsize);   // natural ENOENT
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

// Shared dirfd→path classification for the *at family, the fd→path cache and
// the readlink target resolver live in policy/PathPolicy.m (also used by the
// raw-syscall surface in syscall.x — one resolver for every *at hook).

// The close hook is installed by whichever group installs first (libc or
// libc_lowlevel — both use the fd cache); the guard keeps the second group
// from double-hooking close on the same substitutor.
static BOOL shdw_close_hooked = NO;

static int (*original_close)(int fd);
static int replaced_close(int fd) {
    shdw_fd_cache_invalidate(fd);
    return original_close(fd);
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
        int result = original_chdir(pathname);

        // A successful chdir changes the process cwd: drop the sandbox
        // hook's cached cwd so the next relative-path query resolves
        // against the new one.
        if(result == 0) {
            shdw_sandbox_invalidate_cwd();
        }

        return result;
    }

    errno = ENOENT;
    return -1;
}

static int (*original_fchdir)(int fd);
static int replaced_fchdir(int fd) {
    int result;

    if(!isCallerExternal()) {
        result = original_fchdir(fd);
    } else if(shdw_fd_path_restricted(fd)) {
        errno = EBADF;
        return -1;
    } else {
        result = original_fchdir(fd);
    }

    // A successful fchdir changes the process cwd: drop the sandbox hook's
    // cached cwd so the next relative-path query resolves against the new one.
    if(result == 0) {
        shdw_sandbox_invalidate_cwd();
    }

    return result;
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

    if(ext && [_shadow isCPathRestricted:pathname] && shdw_libc_try_rewrite(pathname)) {
        return original_stat(pathname, buf);   // natural ENOENT
    }

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

    if([_shadow isCPathRestricted:pathname] && shdw_libc_try_rewrite(pathname)) {
        return original_lstat(pathname, buf);   // natural ENOENT
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

    if([_shadow isCPathRestricted:pathname] && shdw_libc_try_rewrite(pathname)) {
        return original_fstatat(dirfd, pathname, buf, flags);   // natural ENOENT
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

    if([_shadow isCPathRestricted:pathname] && shdw_libc_try_rewrite(pathname)) {
        return original_faccessat(dirfd, pathname, mode, flags);   // natural ENOENT
    }

    if(shdw_at_path_denied(dirfd, pathname)) {
        return -1;
    }

    int result = original_faccessat(dirfd, pathname, mode, flags);

    // Restricted-root paths: deny unconditionally for external callers
    if(result != -1) {
        BOOL restricted = [_shadow isCPathRestricted:pathname];
        if(restricted && (shdw_is_restricted_root(pathname) || ext)) {
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

// readdir/readdir_r filtering: the DIR* cache (parent path + options dict,
// denied-vnode fail-closed) lives in policy/PathPolicy.m; the per-entry
// child check runs here, external-caller-gated.

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
        }
    }

    // options is retained by shdw_readdir_cache_options: release on every
    // path after the retain, incl. end-of-stream/error (CFRelease(nil) is a no-op).
    CFRelease((__bridge CFDictionaryRef)options);

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
    }

    // options is retained by shdw_readdir_cache_options: release on every
    // path after the retain, incl. end-of-stream/error (CFRelease(nil) is a no-op).
    CFRelease((__bridge CFDictionaryRef)options);

    return result;
}

static int (*original_closedir)(DIR* dirp);
static int replaced_closedir(DIR* dirp) {
    shdw_readdir_cache_clear(dirp);
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

            // Offset-driven, not record-indexed: dropping a record slides the
            // next one into this offset, so a for(record < result) loop with
            // both record++ and result-- would skip it (the last record then
            // escapes filtering whenever a drop occurs). Re-read from the
            // same offset after a drop; pass 1 already validated every record
            // that can slide in, so the un-bounds-checked reads stay safe.
            while(offset < totalBytes) {
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

// getattrlistat: the *at variant of getattrlist — dirfd+path classified by
// the shared resolver (PathPolicy.m), denied with the same ENOENT the
// path-based getattrlist answers. Absolute paths ignore dirfd; relative
// paths classify the joined dirfd path + "/" + path (a restricted parent
// dirfd makes every entry in it restricted). An unresolvable dirfd replays
// the original call so the kernel reports the genuine EBADF/ENOTDIR.
static int (*original_getattrlistat)(int dirfd, const char* path, void* attrList, void* attrBuf, size_t attrBufSize, unsigned long options);
static int replaced_getattrlistat(int dirfd, const char* path, void* attrList, void* attrBuf, size_t attrBufSize, unsigned long options) {
    if(!isCallerExternal()) {
        return original_getattrlistat(dirfd, path, attrList, attrBuf, attrBufSize, options);
    }

    char parent[PATH_MAX];
    shdw_dirfd_status_t status = shdw_resolve_dirfd_path(dirfd, path, parent, sizeof(parent));

    if(status == SHADW_DIRFD_ORIGINAL) {
        return original_getattrlistat(dirfd, path, attrList, attrBuf, attrBufSize, options);
    }

    if(status == SHADW_DIRFD_DENY) {
        errno = ENOENT;
        return -1;
    }

    if(status == SHADW_DIRFD_ABSOLUTE) {
        if([_shadow isCPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    } else {
        char joined[PATH_MAX * 2];
        int n = snprintf(joined, sizeof(joined), "%s/%s", parent, path);

        // Join overflow: can't classify — pass through (kernel answers).
        if(n > 0 && n < (int) sizeof(joined) && [_shadow isPathRestricted:@(joined) options:nil]) {
            errno = ENOENT;
            return -1;
        }
    }

    return original_getattrlistat(dirfd, path, attrList, attrBuf, attrBufSize, options);
}

// getattrlistbulk: directory-entry enumeration (fs_snapshot_list's sibling
// with the same on-disk record ABI, but the dirfd is app-visible and the
// records carry no paths). The directory itself is judged first: when the
// dirfd's path is restricted, report 0 records with the buffer left
// untouched — the stock empty-directory result (fs_snapshot_list leaves the
// buffer as-is on an empty listing too, so a cleared buffer would be a
// fingerprint). When the dirfd is unrestricted, the returned records are
// post-processed with fs_snapshot_list's shared record ABI: each record's
// name is resolved, joined onto the dirfd's path, and restricted children
// are compacted out of the buffer (memmove tail down, count decremented,
// trailing bytes left untouched — the same compaction fs_snapshot_list
// performs). Records that don't parse — bad length, no name attribute, or
// other returned attributes (a multi-attribute record carries its data in
// request order, so the name reference isn't at the fixed offset) — are
// kept in place (fail open). Snapshot listings pass through untouched:
// fs_snapshot_list is getattrlistbulk with FSOPT_LIST_SNAPSHOTS and is
// hooked separately, owning that case.
//
// FSOPT_LIST_SNAPSHOTS is a private flag, absent from the SDK headers
// (sys/attr.h jumps from FSOPT_PACK_INVAL_ATTRS 0x8 to FSOPT_ATTR_CMN_EXTENDED
// 0x20); value from XNU bsd/sys/attr.h.
#define SHADW_FSOPT_LIST_SNAPSHOTS 0x00000010
static int (*original_getattrlistbulk)(int dirfd, void* attrList, void* attrBuf, size_t attrBufSize, uint64_t flags);
static int replaced_getattrlistbulk(int dirfd, void* attrList, void* attrBuf, size_t attrBufSize, uint64_t flags) {
    if(!isCallerExternal()) {
        return original_getattrlistbulk(dirfd, attrList, attrBuf, attrBufSize, flags);
    }

    if(flags & SHADW_FSOPT_LIST_SNAPSHOTS) {
        return original_getattrlistbulk(dirfd, attrList, attrBuf, attrBufSize, flags);
    }

    if(shdw_fd_path_restricted(dirfd)) {
        return 0;
    }

    // Resolve the dirfd's own path once for the per-record join — the shared
    // *at resolver (shdw_resolve_dirfd_path) classifies dirfd+path pairs, so
    // a bare dirfd is resolved the way that resolver resolves its dirfds:
    // getcwd for AT_FDCWD, F_GETPATH otherwise. An unresolvable dirfd passes
    // through unfiltered (fail open — the fd may be a tty/pipe with no path).
    char dirPath[PATH_MAX];

    if(dirfd == AT_FDCWD) {
        if(!getcwd(dirPath, sizeof(dirPath))) {
            return original_getattrlistbulk(dirfd, attrList, attrBuf, attrBufSize, flags);
        }
    } else if(fcntl(dirfd, F_GETPATH, dirPath) == -1) {
        return original_getattrlistbulk(dirfd, attrList, attrBuf, attrBufSize, flags);
    }

    int result = original_getattrlistbulk(dirfd, attrList, attrBuf, attrBufSize, flags);

    if(result > 0 && attrBuf) {
        // Record layout (mirrors replaced_fs_snapshot_list): uint32 length,
        // attribute_set_t returned attrs, then the name attrreference_t at
        // 4 + sizeof(attribute_set_t) = 24. The returned bitmap is the
        // ATTR_CMN_RETURNED_ATTRS data ("always the first attribute in the
        // return buffer", sys/attr.h), so when the name is the ONLY other
        // attribute returned its reference sits at that fixed offset.
        const uint32_t kNameRefOffset = (uint32_t)(sizeof(uint32_t) + sizeof(attribute_set_t));

        // Pass 1 (bounds): walk `result` records to find the extent of the
        // trusted prefix, stopping at the first record whose length can't be
        // trusted (header out of range, shorter than the header, or extending
        // past the buffer). Everything from there on is kept as-is — fail
        // open, a partially compacted buffer would corrupt the caller's walk.
        uint32_t offset = 0;
        size_t totalBytes = 0;

        for(int record = 0; record < result; record++) {
            if((uint64_t) offset + sizeof(uint32_t) > attrBufSize) {
                break;
            }

            uint32_t recLen;
            memcpy(&recLen, (char*) attrBuf + offset, sizeof(recLen));

            if(recLen < sizeof(uint32_t) + sizeof(attribute_set_t) || (uint64_t) offset + recLen > attrBufSize) {
                break;
            }

            offset += recLen;
            totalBytes = offset;
        }

        // Pass 2 (compact): walk the trusted prefix again. Every record the
        // walk reaches is trustworthy (pass 1 verified the lengths), so no
        // re-validation is needed; a drop shrinks totalBytes by exactly the
        // bytes the tail shifts, so the loop stops where pass 1 stopped.
        // Unlike fs_snapshot_list's for-loop this does NOT advance the
        // record counter on a drop — the record that slides into the dropped
        // slot must be checked too.
        offset = 0;

        while(offset < totalBytes) {
            uint32_t recLen;
            memcpy(&recLen, (char*) attrBuf + offset, sizeof(recLen));

            // Resolve the name only when the returned bitmap says the name
            // attribute was returned AND no other attribute shares the
            // record; otherwise the name reference isn't at offset 24 — keep.
            attribute_set_t returned;
            memcpy(&returned, (char*) attrBuf + offset + sizeof(uint32_t), sizeof(returned));

            if(!(returned.commonattr & ATTR_CMN_NAME)) {
                offset += recLen;  // no name in this record: keep
                continue;
            }

            if((returned.commonattr & ~(ATTR_CMN_NAME | ATTR_CMN_RETURNED_ATTRS)) || returned.fileattr || returned.volattr || returned.dirattr) {
                offset += recLen;  // name not at the fixed offset: keep
                continue;
            }

            // The record must be long enough to hold the reference.
            if(recLen < kNameRefOffset + (uint32_t) sizeof(attrreference_t)) {
                offset += recLen;  // reference outside the record: keep
                continue;
            }

            attrreference_t nameRef;
            memcpy(&nameRef, (char*) attrBuf + offset + kNameRefOffset, sizeof(nameRef));

            if(nameRef.attr_dataoffset < (int32_t) sizeof(nameRef)) {
                offset += recLen;  // malformed reference: keep
                continue;
            }

            // The NUL-terminated name string must fit inside the record.
            uint32_t nameOffset = (uint32_t) nameRef.attr_dataoffset;

            if((uint64_t) nameOffset + 1 > (uint64_t) recLen - kNameRefOffset) {
                offset += recLen;  // name outside the record: keep
                continue;
            }

            const char* nameStr = (char*) attrBuf + offset + kNameRefOffset + nameOffset;

            // Bound the scan by the record tail AND the kernel-reported
            // attribute length; the NUL must be found within the bound
            // (fs_snapshot_list's check).
            size_t avail = recLen - kNameRefOffset - nameOffset;

            if(nameRef.attr_length < avail) {
                avail = nameRef.attr_length;
            }

            if(strnlen(nameStr, avail) == avail) {
                offset += recLen;  // no NUL within the bounded name: keep
                continue;
            }

            // Join the entry onto the dirfd's path; a restricted child is
            // compacted out: shift the tail down over the record, the next
            // record now starts at the same offset (fs_snapshot_list's
            // compaction; trailing bytes stay untouched).
            char joined[PATH_MAX * 2];
            int n = snprintf(joined, sizeof(joined), "%s/%s", dirPath, nameStr);

            if(n <= 0 || n >= (int) sizeof(joined)) {
                offset += recLen;  // join overflow: can't classify — keep
                continue;
            }

            // Per-record pool: @(joined) and the restriction check
            // autorelease per record; without it raw-pthread callers (no
            // pool) leak every skipped name (readdir's pattern).
            @autoreleasepool {
                if([_shadow isPathRestricted:@(joined) options:nil]) {
                    memmove((char*) attrBuf + offset, (char*) attrBuf + offset + recLen, totalBytes - (offset + recLen));
                    totalBytes -= recLen;
                    result--;
                    continue;
                }
            }

            offset += recLen;
        }
    }

    return result;
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

// JIT gap: when the app makes a range executable, scan it for raw svc sites
// immediately (the svc patcher's periodic VM re-scan would otherwise race
// the detector's first probe). The scan itself is a no-op unless the
// Hook_Syscall-gated patcher installed. Non-path svc sites pass through the
// trampoline untouched, so JIT engines that emit svc (e.g. JSC) are
// unaffected beyond a per-call trampoline hop.
static int (*original_mprotect)(void* addr, size_t len, int prot);
static int replaced_mprotect(void* addr, size_t len, int prot) {
    int ret = original_mprotect(addr, len, prot);

    if(ret == 0 && (prot & PROT_EXEC)) {
        shdw_svc_scan_range((uintptr_t)addr, len);
    }

    return ret;
}

// One descriptor array is the SINGLE source of truth for every libc hook's
// install (which group hooks it), post-install verification (which group
// treats a NULL original as a failure) and the dlsym symbol policy (every
// entry is exposed through shdw_sym_policy_lookup_libc, guarded by its
// original pointer). Symbols are resolved with dlsym at install time:
// required exports always resolve, and runtime-conditional symbols that are
// absent on a given OS (stat64 family, protected-open variants, libproc,
// getmntinfo_r_np, utimensat on < iOS 11) are skipped cleanly — NULL there
// is expected and never a verify failure (verifyGroups = 0).
//
// Group semantics, byte-identical to the old per-group code:
//   - close is installed by whichever of libc / libc_lowlevel runs first
//     (the shdw_close_hooked guard still enforces single install), and is
//     verified by libc_lowlevel only;
//   - utimensat is installed but excluded from verify (it was iOS-11-gated
//     with an @available check; dlsym is that check now);
//   - the optional runtime-resolved families are installed, never verified.
typedef struct {
    const char* symbol;     // dlsym name (C identifier, unmangled)
    void* replacement;      // the hook replacement
    void** original;        // original-slot out pointer
    uint32_t installGroups; // bitmask: hooked when one of these groups installs
    uint32_t verifyGroups;  // bitmask: NULL original is a verify failure here (required)
} shdw_hook_desc_t;

#define LIBC   SHADW_HOOK_GROUP_LIBC
#define ENVVAR SHADW_HOOK_GROUP_ENVVAR
#define LOW    SHADW_HOOK_GROUP_LOWLEVEL
#define ANTIDBG SHADW_HOOK_GROUP_ANTIDEBUG

static const shdw_hook_desc_t shdw_libc_hooks[] = {
    // required libc group (installed + verified by libc)
    { "access",                 (void*)&replaced_access,                   (void**)&original_access,                   LIBC,   LIBC },
    { "chdir",                  (void*)&replaced_chdir,                    (void**)&original_chdir,                    LIBC,   LIBC },
    { "chroot",                 (void*)&replaced_chroot,                   (void**)&original_chroot,                   LIBC,   LIBC },
    { "creat",                  (void*)&replaced_creat,                    (void**)&original_creat,                    LIBC,   LIBC },
    { "statfs",                 (void*)&replaced_statfs,                   (void**)&original_statfs,                   LIBC,   LIBC },
    { "fstatfs",                (void*)&replaced_fstatfs,                  (void**)&original_fstatfs,                  LIBC,   LIBC },
    { "statvfs",                (void*)&replaced_statvfs,                  (void**)&original_statvfs,                  LIBC,   LIBC },
    { "fstatvfs",               (void*)&replaced_fstatvfs,                 (void**)&original_fstatvfs,                 LIBC,   LIBC },
    { "stat",                   (void*)&replaced_stat,                     (void**)&original_stat,                     LIBC,   LIBC },
    { "lstat",                  (void*)&replaced_lstat,                    (void**)&original_lstat,                    LIBC,   LIBC },
    { "faccessat",              (void*)&replaced_faccessat,                (void**)&original_faccessat,                LIBC,   LIBC },
    { "readdir_r",              (void*)&replaced_readdir_r,                (void**)&original_readdir_r,                LIBC,   LIBC },
    { "readdir",                (void*)&replaced_readdir,                  (void**)&original_readdir,                  LIBC,   LIBC },
    { "closedir",               (void*)&replaced_closedir,                 (void**)&original_closedir,                 LIBC,   LIBC },
    { "fopen",                  (void*)&replaced_fopen,                    (void**)&original_fopen,                    LIBC,   LIBC },
    { "freopen",                (void*)&replaced_freopen,                  (void**)&original_freopen,                  LIBC,   LIBC },
    { "realpath",               (void*)&replaced_realpath,                 (void**)&original_realpath,                 LIBC,   LIBC },
    { "readlink",               (void*)&replaced_readlink,                 (void**)&original_readlink,                 LIBC,   LIBC },
    { "readlinkat",             (void*)&replaced_readlinkat,               (void**)&original_readlinkat,               LIBC,   LIBC },
    { "link",                   (void*)&replaced_link,                     (void**)&original_link,                     LIBC,   LIBC },
    { "getmntinfo",             (void*)&replaced_getmntinfo,               (void**)&original_getmntinfo,               LIBC,   LIBC },
    { "getattrlist",            (void*)&replaced_getattrlist,              (void**)&original_getattrlist,              LIBC,   LIBC },
    { "fs_snapshot_list",       (void*)&replaced_fs_snapshot_list,         (void**)&original_fs_snapshot_list,         LIBC,   LIBC },
    { "getxattr",               (void*)&replaced_getxattr,                 (void**)&original_getxattr,                 LIBC,   LIBC },
    { "listxattr",              (void*)&replaced_listxattr,                (void**)&original_listxattr,                LIBC,   LIBC },
    { "fgetxattr",              (void*)&replaced_fgetxattr,                (void**)&original_fgetxattr,                LIBC,   LIBC },
    { "flistxattr",             (void*)&replaced_flistxattr,               (void**)&original_flistxattr,               LIBC,   LIBC },
    { "fgetattrlist",           (void*)&replaced_fgetattrlist,             (void**)&original_fgetattrlist,             LIBC,   LIBC },
    { "getattrlistat",          (void*)&replaced_getattrlistat,            (void**)&original_getattrlistat,            LIBC,   LIBC },
    { "getattrlistbulk",        (void*)&replaced_getattrlistbulk,          (void**)&original_getattrlistbulk,          LIBC,   LIBC },
    { "symlink",                (void*)&replaced_symlink,                  (void**)&original_symlink,                  LIBC,   LIBC },
    { "rename",                 (void*)&replaced_rename,                   (void**)&original_rename,                   LIBC,   LIBC },
    { "remove",                 (void*)&replaced_remove,                   (void**)&original_remove,                   LIBC,   LIBC },
    { "unlink",                 (void*)&replaced_unlink,                   (void**)&original_unlink,                   LIBC,   LIBC },
    { "unlinkat",               (void*)&replaced_unlinkat,                 (void**)&original_unlinkat,                 LIBC,   LIBC },
    { "linkat",                 (void*)&replaced_linkat,                   (void**)&original_linkat,                   LIBC,   LIBC },
    { "symlinkat",              (void*)&replaced_symlinkat,                (void**)&original_symlinkat,                LIBC,   LIBC },
    { "renameat",               (void*)&replaced_renameat,                 (void**)&original_renameat,                 LIBC,   LIBC },
    { "mkdirat",                (void*)&replaced_mkdirat,                  (void**)&original_mkdirat,                  LIBC,   LIBC },
    { "fchmodat",               (void*)&replaced_fchmodat,                 (void**)&original_fchmodat,                 LIBC,   LIBC },
    { "rmdir",                  (void*)&replaced_rmdir,                    (void**)&original_rmdir,                    LIBC,   LIBC },
    { "pathconf",               (void*)&replaced_pathconf,                 (void**)&original_pathconf,                 LIBC,   LIBC },
    { "fpathconf",              (void*)&replaced_fpathconf,                (void**)&original_fpathconf,                LIBC,   LIBC },
    { "utimes",                 (void*)&replaced_utimes,                   (void**)&original_utimes,                   LIBC,   LIBC },
    { "futimes",                (void*)&replaced_futimes,                  (void**)&original_futimes,                  LIBC,   LIBC },
    { "fchdir",                 (void*)&replaced_fchdir,                   (void**)&original_fchdir,                   LIBC,   LIBC },
    { "getfsstat",              (void*)&replaced_getfsstat,                (void**)&original_getfsstat,                LIBC,   LIBC },
    { "fstat",                  (void*)&replaced_fstat,                    (void**)&original_fstat,                    LIBC,   LIBC },
    { "fstatat",                (void*)&replaced_fstatat,                  (void**)&original_fstatat,                  LIBC,   LIBC },
    { "mprotect",               (void*)&replaced_mprotect,                 (void**)&original_mprotect,                 LIBC,   LIBC },

    // installed-only (verification excluded, matching the old code's exempt lists)
    { "utimensat",              (void*)&replaced_utimensat,                (void**)&original_utimensat,                LIBC,   0 },   // iOS 11+ gate: dlsym is the availability check
    { "getmntinfo_r_np",        (void*)&shdw_replaced_getmntinfo_r_np,     (void**)&original_getmntinfo_r_np,          LIBC,   0 },   // iOS 16+ export

    // envvar group
    { "getenv",                 (void*)&replaced_getenv,                   (void**)&original_getenv,                   ENVVAR, ENVVAR },

    // lowlevel group
    { "open",                   (void*)&replaced_open,                     (void**)&original_open,                     LOW,    LOW },
    { "openat",                 (void*)&replaced_openat,                   (void**)&original_openat,                   LOW,    LOW },
    { "opendir",                (void*)&replaced_opendir,                  (void**)&original_opendir,                  LOW,    LOW },
    { "__opendir2",             (void*)&replaced___opendir2,               (void**)&original___opendir2,               LOW,    LOW },
    { "open_dprotected_np",     (void*)&replaced_open_dprotected_np,       (void**)&original_open_dprotected_np,       LOW,    0 },
    { "openat_dprotected_np",   (void*)&replaced_openat_dprotected_np,     (void**)&original_openat_dprotected_np,     LOW,    0 },
    { "openat_authenticated_np",(void*)&replaced_openat_authenticated_np,  (void**)&original_openat_authenticated_np,  LOW,    0 },
    { "stat64",                 (void*)&replaced_stat64,                   (void**)&original_stat64,                   LOW,    0 },
    { "lstat64",                (void*)&replaced_lstat64,                  (void**)&original_lstat64,                  LOW,    0 },
    { "fstat64",                (void*)&replaced_fstat64,                  (void**)&original_fstat64,                  LOW,    0 },
    { "fstatat64",              (void*)&replaced_fstatat64,                (void**)&original_fstatat64,                LOW,    0 },

    // close: installed by whichever of libc / lowlevel runs first
    { "close",                  (void*)&replaced_close,                    (void**)&original_close,                    LIBC | LOW, LOW },

    // antidebugging group
    { "ptrace",                 (void*)&replaced_ptrace,                   (void**)&original_ptrace,                   ANTIDBG,  ANTIDBG },
    { "sysctl",                 (void*)&replaced_sysctl,                   (void**)&original_sysctl,                   ANTIDBG,  ANTIDBG },
    { "getppid",                (void*)&replaced_getppid,                  (void**)&original_getppid,                  ANTIDBG,  ANTIDBG },
    { "getrusage",              (void*)&replaced_getrusage,                (void**)&original_getrusage,                ANTIDBG,  ANTIDBG },
    { "getrlimit",              (void*)&replaced_getrlimit,                (void**)&original_getrlimit,                ANTIDBG,  ANTIDBG },
    { "proc_listpids",          (void*)&replaced_proc_listpids,            (void**)&original_proc_listpids,            ANTIDBG,  0 },
    { "proc_listallpids",       (void*)&replaced_proc_listallpids,         (void**)&original_proc_listallpids,         ANTIDBG,  0 },
    { "proc_pidinfo",           (void*)&replaced_proc_pidinfo,             (void**)&original_proc_pidinfo,             ANTIDBG,  0 },
};

#undef LIBC
#undef ENVVAR
#undef LOW
#undef ANTIDBG

void shdw_libc_install_group(HKSubstitutor* hooks, uint32_t group) {
    // Hook installs re-enter hooked libc functions: the backend's symbol
    // resolution (dyld image walk) and Foundation file APIs call
    // getppid/getrusage/sysctl/stat/fopen — which are themselves hooked by
    // this or earlier groups. Their replacements consult isCallerExternal()
    // and run the restriction engine, which during ctor-time install can
    // re-enter the installer or hit half-installed state (SIGSEGV at PC=0
    // observed on-device). Mark the install as an internal read so those
    // replacements short-circuit to their originals.
    [Shadow shdwEnterInternalRead];
    for(size_t i = 0; i < sizeof(shdw_libc_hooks) / sizeof(shdw_libc_hooks[0]); i++) {
        const shdw_hook_desc_t* d = &shdw_libc_hooks[i];

        if(!(d->installGroups & group)) {
            continue;
        }

        if(strcmp(d->symbol, "close") == 0 && shdw_close_hooked) {
            continue;  // already installed by the other group
        }

        // Runtime-resolve; absent optional symbols skip cleanly, absent
        // required ones surface in the group's verify pass.
        void* target = dlsym(RTLD_DEFAULT, d->symbol);

        if(!target) {
            continue;
        }

        // Optional compatibility exports may resolve to a modern alias
        // (stat64 -> stat) or an interior/private address. Installing a
        // second fishhook entry under the alias name can never match the
        // requested symbol and only reports a false backend failure.
        if(d->verifyGroups == 0) {
            Dl_info info;
            if(!dladdr(target, &info) || !info.dli_sname || info.dli_saddr != target) {
                continue;
            }

            const char* resolved = info.dli_sname[0] == '_' ? info.dli_sname + 1 : info.dli_sname;
            if(strcmp(resolved, d->symbol) != 0) {
                continue;
            }
        }

        [hooks hookFunction:target withReplacement:d->replacement outOldPtr:d->original];

        if(strcmp(d->symbol, "close") == 0) {
            shdw_close_hooked = YES;
        }
    }
    [Shadow shdwExitInternalRead];
}

void shdw_libc_verify_group(const char* group, uint32_t mask) {
    for(size_t i = 0; i < sizeof(shdw_libc_hooks) / sizeof(shdw_libc_hooks[0]); i++) {
        const shdw_hook_desc_t* d = &shdw_libc_hooks[i];

        if((d->verifyGroups & mask) && d->original && *d->original == NULL) {
            NSLog(@"[Shadow] %s hook not installed: %s", group, d->symbol);
        }
    }
}

void shadowhook_libc(HKSubstitutor* hooks) {
    shdw_libc_install_group(hooks, SHADW_HOOK_GROUP_LIBC);
}

// Post-install verification: a hook that failed to install (backend error,
// symbol unresolvable) leaves its original_* NULL and the restriction
// silently unenforced. The ctor calls these after executeHooks for the groups
// it installed; each logs any NULL among the group's required symbols.
// Runtime-resolved optional symbols (stat64 family, protected-open variants,
// getmntinfo_r_np, libproc, utimensat) are excluded — NULL there is expected.
void shadowhook_libc_verify(void) {
    shdw_libc_verify_group("libc", SHADW_HOOK_GROUP_LIBC);
}

// Symbol policy for the libc C-function groups (see dyld.x's
// shdw_sym_policy_table): dlsym must resolve every fishhook-rebound libc
// export to its replacement for external callers, so the GOT-vs-dlsym
// comparison agrees. Guarded by the original pointer: a symbol only resolves
// to its replacement when the hook actually installed (original != NULL), so
// runtime-conditional symbols that are absent on a given OS stay absent.
void* shdw_sym_policy_lookup_libc(const char* name) {
    if(!name) {
        return NULL;
    }

    for(size_t i = 0; i < sizeof(shdw_libc_hooks) / sizeof(shdw_libc_hooks[0]); i++) {
        const shdw_hook_desc_t* d = &shdw_libc_hooks[i];

        if(strcmp(name, d->symbol) == 0) {
            if(d->original && *d->original == NULL) {
                return NULL;  // runtime-conditional symbol not installed
            }

            return d->replacement;
        }
    }

    return NULL;
}
