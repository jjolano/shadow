#import "hooks.h"
#import "../../policy/PathPolicy.h"

#import <string.h>
#import <stdlib.h>

// freeRASP rootless probe (.jbroot write): the classifier lives in
// policy/PathPolicy.m (shdw_is_jbroot_write_probe), shared with the open
// family hooks below.

int (*original_open)(const char *pathname, int oflag, ...);
int replaced_open(const char *pathname, int oflag, ...) {
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

    // Natural-ENOENT rewrite: only without O_CREAT (the munged path would
    // otherwise be CREATED as a side effect).
    if(!(oflag & O_CREAT) && shdw_libc_try_rewrite(pathname)) {
        return original_open(pathname, oflag);   // natural ENOENT
    }

    errno = ENOENT;
    return -1;
}

int (*original_openat)(int dirfd, const char *pathname, int oflag, ...);
int replaced_openat(int dirfd, const char *pathname, int oflag, ...) {
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

    // Natural-ENOENT rewrite: only without O_CREAT (the munged path would
    // otherwise be CREATED as a side effect).
    if(!(oflag & O_CREAT) && shdw_libc_try_rewrite(pathname)) {
        return original_openat(dirfd, pathname, oflag);   // natural ENOENT
    }

    if(oflag & O_CREAT) {
        return original_openat(dirfd, pathname, oflag, mode);
    }

    // Restricted-root paths: deny unconditionally for external callers
    if([_shadow isCPathRestricted:pathname] && (shdw_is_restricted_root(pathname) || ext)) {
        errno = ENOENT;
        return -1;
    }

    return original_openat(dirfd, pathname, oflag);
}

DIR* (*original___opendir2)(const char* pathname, int flags);
DIR* replaced___opendir2(const char* pathname, int flags) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original___opendir2(pathname, flags);
    }

    errno = ENOENT;
    return NULL;
}

// Public opendir: libSystem's public opendir() may call the private
// __opendir2 internally WITHOUT going through the rebindable PLT entry (the
// fishhook lane only intercepts import-table references), so hooking only
// __opendir2 leaves the public API visible to detectors that call opendir()
// directly (observed via the hookprobe battery: opendir("/var/jb") returned
// a handle while stat/open on the same path were filtered). Hook the public
// symbol too; when it is a weak alias of __opendir2 both entries chain to
// the same replacement, and the guard keeps the redirect idempotent.
DIR* (*original_opendir)(const char* pathname);
DIR* replaced_opendir(const char* pathname) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_opendir(pathname);
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

int (*original_stat64)(const char* pathname, shdw_stat64_t* buf);
int replaced_stat64(const char* pathname, shdw_stat64_t* buf) {
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

int (*original_lstat64)(const char* pathname, shdw_stat64_t* buf);
int replaced_lstat64(const char* pathname, shdw_stat64_t* buf) {
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

int (*original_fstat64)(int fd, shdw_stat64_t* buf);
int replaced_fstat64(int fd, shdw_stat64_t* buf) {
    if(!isCallerExternal()) {
        return original_fstat64(fd, buf);
    }

    if(shdw_fd_path_restricted(fd)) {
        errno = EBADF;
        return -1;
    }

    return original_fstat64(fd, buf);
}

int (*original_fstatat64)(int dirfd, const char* pathname, shdw_stat64_t* buf, int flags);
int replaced_fstatat64(int dirfd, const char* pathname, shdw_stat64_t* buf, int flags) {
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

int (*original_open_dprotected_np)(const char* path, int flags, int class, int dpflags, ...);
int replaced_open_dprotected_np(const char* path, int flags, int class, int dpflags, ...) {
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

int (*original_openat_dprotected_np)(int dirfd, const char* path, int flags, int class, int dpflags, ...);
int replaced_openat_dprotected_np(int dirfd, const char* path, int flags, int class, int dpflags, ...) {
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

int (*original_openat_authenticated_np)(int dirfd, const char* path, struct ad_open_auth* auth, int flags, ...);
int replaced_openat_authenticated_np(int dirfd, const char* path, struct ad_open_auth* auth, int flags, ...) {
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

void shadowhook_libc_lowlevel(HKSubstitutor* hooks) {
    shdw_libc_install_group(hooks, SHADW_HOOK_GROUP_LOWLEVEL);
}

void shadowhook_libc_lowlevel_verify(void) {
    shdw_libc_verify_group("libc_lowlevel", SHADW_HOOK_GROUP_LOWLEVEL);
}
