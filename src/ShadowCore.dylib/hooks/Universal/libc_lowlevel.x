#import "UniversalHooks.h"
#import <stdarg.h>
#import "../../policy/PathPolicy.h"

#import <string.h>
#import <stdlib.h>
#import <unistd.h>

int (*original_open)(const char *pathname, int oflag, ...);
int replaced_open(const char *pathname, int oflag, ...) {
    BOOL ext = isCallerExternal();
    // Resolve-stable fast lane: verify the handed-out fd (it already
    // exists — no extra lookup), so a planted link under a writable
    // prefix hides like its target. (Write policy and ruleset verdicts
    // are not consulted on this lane, exactly as before.)
    if(shdw_is_fast_allowed_cpath(pathname)) {
        int fd;
        if(oflag & O_CREAT) {
            va_list ap; va_start(ap, oflag); mode_t m = (mode_t)va_arg(ap, int); va_end(ap);
            fd = original_open(pathname, oflag, m);
        } else {
            fd = original_open(pathname, oflag);
        }
        if(fd >= 0 && ext && shdw_fd_names_hidden(fd)) {
            close(fd);
            errno = ENOENT;
            return -1;
        }
        return fd;
    }
    SHADOW_TRIP(pathname, "open", ext);

    mode_t mode = 0;
    if(oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }

    if(ext && (oflag & O_CREAT) && shdw_detector_c_write_path_denied(pathname)) {
        errno = ENOENT;
        return -1;
    }

    if(ext && shdw_path_is_main_bundle_exempt(pathname)) {
        if(oflag & O_CREAT) {
            return original_open(pathname, oflag, mode);
        }
        return original_open(pathname, oflag);
    }

    // Same external-hidden set the stat/access hooks apply: an object hidden
    // from every absolute probe must not be openable by an external caller.
    // The denial traps first (a side-effect-free read-only open, never CREAT)
    // and denies after, so it costs the same trapped lookup as an absent path.
    if(ext && shdw_path_is_external_hidden_lexical(pathname)) {
        [_shadow isCPathRestricted:pathname];
        int tfd = original_open(pathname, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if(tfd >= 0) {
            close(tfd);
        }
        errno = ENOENT;
        return -1;
    }

    if(!ext || ![_shadow isCPathRestricted:pathname]) {
        int fd;
        if(oflag & O_CREAT) {
            fd = original_open(pathname, oflag, mode);
        } else {
            fd = original_open(pathname, oflag);
        }
        // Verify-after-use (alias TOCTOU): the handed-out fd, not the
        // request spelling, decides. Deterministic: the fd pins the object.
        if(fd >= 0 && ext && shdw_fd_names_hidden(fd)) {
            close(fd);
            errno = ENOENT;
            return -1;
        }
        return fd;
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
    if(oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }

    if(!ext) {
        if(oflag & O_CREAT) {
            return original_openat(dirfd, pathname, oflag, mode);
        }

        return original_openat(dirfd, pathname, oflag);
    }

    if((oflag & O_CREAT) && shdw_detector_c_write_path_denied(pathname)) {
        errno = ENOENT;
        return -1;
    }

    if(pathname && pathname[0] == '/') {
        if(shdw_path_is_main_bundle_exempt(pathname)) {
            if(oflag & O_CREAT) {
                return original_openat(dirfd, pathname, oflag, mode);
            }
            return original_openat(dirfd, pathname, oflag);
        }
    } else if(pathname && pathname[0] != '\0') {
        char parent[PATH_MAX];
        shdw_dirfd_status_t st = shdw_resolve_dirfd_path(dirfd, pathname, parent, sizeof(parent));
        if(st == SHADW_DIRFD_OK) {
            char joined[PATH_MAX * 2];
            int n = snprintf(joined, sizeof(joined), "%s/%s", parent, pathname);
            if(n > 0 && n < (int)sizeof(joined) && shdw_path_is_main_bundle_exempt(joined)) {
                if(oflag & O_CREAT) {
                    return original_openat(dirfd, pathname, oflag, mode);
                }
                return original_openat(dirfd, pathname, oflag);
            }
        }
    }

    if(shdw_at_path_denied(dirfd, pathname)) {
        return -1;
    }

    int fd;
    if(oflag & O_CREAT) {
        fd = original_openat(dirfd, pathname, oflag, mode);
    } else if([_shadow isCPathRestricted:pathname] && (shdw_is_restricted_root(pathname) || ext)) {
        // Restricted-root paths: deny unconditionally for external callers
        errno = ENOENT;
        return -1;
    } else {
        fd = original_openat(dirfd, pathname, oflag);
    }
    // Verify-after-use (alias TOCTOU): the handed-out fd decides.
    if(fd >= 0 && ext && shdw_fd_names_hidden(fd)) {
        close(fd);
        errno = ENOENT;
        return -1;
    }
    return fd;
}

int (*original_open_nocancel)(const char *pathname, int oflag, ...);
int replaced_open_nocancel(const char *pathname, int oflag, ...) {
    mode_t mode = 0;
    if(oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }
    BOOL ext = isCallerExternal();
    if(ext && shdw_path_is_main_bundle_exempt(pathname)) {
        if(oflag & O_CREAT) return original_open_nocancel(pathname, oflag, mode);
        return original_open_nocancel(pathname, oflag);
    }
    if(ext && shdw_path_is_external_hidden_lexical(pathname)) {
        errno = ENOENT;
        return -1;
    }
    if(!ext || ![_shadow isCPathRestricted:pathname]) {
        int fd;
        if(oflag & O_CREAT) fd = original_open_nocancel(pathname, oflag, mode);
        else fd = original_open_nocancel(pathname, oflag);
        // Verify-after-use (alias TOCTOU): the handed-out fd decides.
        if(fd >= 0 && ext && shdw_fd_names_hidden(fd)) {
            close(fd);
            errno = ENOENT;
            return -1;
        }
        return fd;
    }
    errno = ENOENT;
    return -1;
}

int (*original_openat_nocancel)(int dirfd, const char *pathname, int oflag, ...);
int replaced_openat_nocancel(int dirfd, const char *pathname, int oflag, ...) {
    mode_t mode = 0;
    if(oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }
    BOOL ext = isCallerExternal();
    if(!ext) {
        if(oflag & O_CREAT) return original_openat_nocancel(dirfd, pathname, oflag, mode);
        return original_openat_nocancel(dirfd, pathname, oflag);
    }
    if(shdw_at_path_denied(dirfd, pathname)) return -1;
    int fd;
    if(oflag & O_CREAT) fd = original_openat_nocancel(dirfd, pathname, oflag, mode);
    else fd = original_openat_nocancel(dirfd, pathname, oflag);
    // Verify-after-use (alias TOCTOU): the handed-out fd decides.
    if(fd >= 0 && ext && shdw_fd_names_hidden(fd)) {
        close(fd);
        errno = ENOENT;
        return -1;
    }
    return fd;
}

DIR* (*original___opendir2)(const char* pathname, int flags);
DIR* replaced___opendir2(const char* pathname, int flags) {
    BOOL ext = isCallerExternal();
    // Same own-bundle exemption as the open/stat family: an app whose bundle
    // lives under a restricted root must be able to list its own resources.
    if(ext && shdw_path_is_main_bundle_exempt(pathname)) {
        return original___opendir2(pathname, flags);
    }
    if(!ext || ![_shadow isCPathRestricted:pathname]) {
        DIR* dp = original___opendir2(pathname, flags);
        // Verify-after-use (alias TOCTOU): the handed-out DIR decides.
        if(dp && ext && shdw_fd_names_hidden(dirfd(dp))) {
            closedir(dp);
            errno = ENOENT;
            return NULL;
        }
        return dp;
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
    BOOL ext = isCallerExternal();
    // Same own-bundle exemption as the open/stat family: an app whose bundle
    // lives under a restricted root must be able to list its own resources.
    if(ext && shdw_path_is_main_bundle_exempt(pathname)) {
        return original_opendir(pathname);
    }
    if(!ext || ![_shadow isCPathRestricted:pathname]) {
        DIR* dp = original_opendir(pathname);
        // Verify-after-use (alias TOCTOU): the handed-out DIR decides.
        if(dp && ext && shdw_fd_names_hidden(dirfd(dp))) {
            closedir(dp);
            errno = ENOENT;
            return NULL;
        }
        return dp;
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

// Forward declaration: the fstat64 hook slot below, used by the verifier.
int (*original_fstat64)(int fd, shdw_stat64_t* buf);

// 64-bit twin of shdw_stat_substitute (see libc.x): same pin-the-object
// contract over the legacy 64-bit layout.
static int shdw_stat64_substitute(int dirfd, const char* pathname, shdw_stat64_t* buf, int flags) {
    if((flags & AT_SYMLINK_NOFOLLOW) != 0) return -2;
    int vfd = openat(dirfd, pathname, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if(vfd < 0 && errno != ENOENT) {
        // One retry (see libc.x twin): transient race artifacts convert.
        vfd = openat(dirfd, pathname, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    }
    if(vfd < 0) {
        // Verifier-ENOENT answers directly (anti-flip; see libc.x twin).
        if(errno == ENOENT) {
            memset(buf, 0, sizeof(shdw_stat64_t));
            return -1;
        }
        return -2;
    }
    char canon[PATH_MAX];
    int r = -2;
    if(fcntl(vfd, F_GETPATH, canon) != -1) {
        if(shdw_resolved_spelling_hidden(canon)) {
            memset(buf, 0, sizeof(shdw_stat64_t));
            errno = ENOENT;
            r = -1;
        } else if(original_fstat64(vfd, buf) == 0) {
            r = 0;
        }
        // else: fstat/unresolvable — fall back below.
    }
    close(vfd);
    return r;
}
int (*original_stat64)(const char* pathname, shdw_stat64_t* buf);
int replaced_stat64(const char* pathname, shdw_stat64_t* buf) {
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "stat64", ext);

    // Same own-bundle exemption as the open family (see replaced_access in
    // libc.x): Foundation's fileExists/contents go through these *64 forms,
    // so without it an app could open its own bundle resources but not see
    // them, a shape divergence that reads as jailbreak evidence.
    if(ext && shdw_path_is_main_bundle_exempt(pathname)) {
        return original_stat64(pathname, buf);
    }

    BOOL hidden = ext && shdw_path_is_external_hidden_lexical(pathname);

    shdw_stat64_t trapbuf;
    int result;
    int sub = -2;
    // Fully allowed, buffered lookup of a resolution-unstable spelling:
    // answer from the pinned object (deterministic); anything else takes
    // the original path below (see replaced_stat in libc.x for the shape).
    if(!hidden && ext && buf && shdw_path_needs_verify(pathname)) {
        sub = shdw_stat64_substitute(AT_FDCWD, pathname, buf, 0);
    }
    if(sub != -2) {
        result = sub;
    } else {
        result = original_stat64(pathname, hidden ? &trapbuf : buf);
    }
    if(hidden) {
        errno = ENOENT;
        return -1;
    }

    if(result != -1 && ext && [_shadow isCPathRestricted:pathname]) {
        if(buf) {
            memset(buf, 0, sizeof(shdw_stat64_t));
        }

        errno = ENOENT;
        return -1;
    }
    // Bounded re-verification: only when substitution did not already
    // answer from a pinned object (its verdict is final — re-sampling
    // could only re-open a window the substitution closed). On immutable
    // spellings, where substitution never runs, this same sample keeps
    // the success legs at the same resolving-work shape instead.
    if(sub == -2 && result != -1 && ext && !hidden && buf &&
        shdw_at_post_verify(AT_FDCWD, pathname) != SHDW_POST_ADMIT) {
        memset(buf, 0, sizeof(shdw_stat64_t));
        errno = ENOENT;
        return -1;
    }

    // Gap 2: a stock system directory bind-shadowed by a jailbreak fakelib
    // gets its own filesystem id; equalise it with the covering rootfs so a
    // parent/child st_dev split can't reveal the bind. Only for the covered
    // system prefixes, only when the id actually diverges from rootfs.
    if(result != -1 && ext && buf && shdw_path_under_system_bind_root(pathname)) {
        dev_t rootdev = shdw_rootfs_dev();
        if(rootdev != 0 && (dev_t)buf->st_dev != rootdev) {
            buf->st_dev = (typeof(buf->st_dev))rootdev;
        }
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

    // Same own-bundle exemption as the open family (see replaced_stat64).
    if(shdw_path_is_main_bundle_exempt(pathname)) {
        return original_lstat64(pathname, buf);
    }

    BOOL hidden = shdw_path_is_external_hidden_lexical(pathname);

    // NULL caller buffer keeps stock semantics (EFAULT from the kernel);
    // replay before classification. A hidden path still answers ENOENT: it
    // traps into scratch below.
    if(!hidden && buf == NULL) {
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

        if(shdw_path_under_system_bind_root(pathname)) {
            dev_t rootdev = shdw_rootfs_dev();
            if(rootdev != 0 && (dev_t)_buf.st_dev != rootdev) {
                _buf.st_dev = (typeof(_buf.st_dev))rootdev;
            }
        }

        // A hidden denial traps first and denies after, so it costs the
        // same trapped lookup as a genuinely-absent path.
        if(hidden) {
            errno = ENOENT;
            return -1;
        }
        // Verify-after-use (alias TOCTOU): bounded post re-check.
        if(!hidden && shdw_path_post_hidden(pathname)) {
            errno = ENOENT;
            return -1;
        }

        // Only copy on success: on failure _buf is uninitialized stack.
        memcpy(buf, &_buf, sizeof(shdw_stat64_t));
    }

    if(hidden) {
        errno = ENOENT;
        return -1;
    }

    return result;
}

int (*original_fstat64)(int fd, shdw_stat64_t* buf);
int replaced_fstat64(int fd, shdw_stat64_t* buf) {
    if(!isCallerExternal()) {
        return original_fstat64(fd, buf);
    }

    // Same own-bundle exemption as the path sibling (see replaced_stat64).
    if(shdw_fd_path_bundle_exempt(fd)) {
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

    // Same own-bundle exemption as the open family (see replaced_stat64);
    // absolute operands only — relative ones resolve through the dirfd.
    if(shdw_path_is_absolute(pathname) && shdw_path_is_main_bundle_exempt(pathname)) {
        return original_fstatat64(dirfd, pathname, buf, flags);
    }

    BOOL hidden = shdw_path_is_absolute(pathname) && shdw_path_is_external_hidden_lexical(pathname);

    // Relative operands joining onto the caller's own bundle pass through,
    // mirroring the absolute exemption above (same shape as replaced_openat).
    if(!hidden && !shdw_path_is_absolute(pathname) && pathname && pathname[0] != '\0') {
        char parent[PATH_MAX];
        if(shdw_resolve_dirfd_path(dirfd, pathname, parent, sizeof(parent)) == SHADW_DIRFD_OK) {
            char joined[PATH_MAX * 2];
            int n = snprintf(joined, sizeof(joined), "%s/%s", parent, pathname);
            if(n > 0 && n < (int)sizeof(joined) && shdw_path_is_main_bundle_exempt(joined)) {
                return original_fstatat64(dirfd, pathname, buf, flags);
            }
        }
    }

    if(!hidden && shdw_at_path_denied(dirfd, pathname)) {
        return -1;
    }

    // A hidden denial traps into scratch and denies after, so it costs the
    // same trapped lookup as a genuinely-absent path.
    shdw_stat64_t trapbuf;
    int result;
    int sub = -2;
    // Fully allowed, follow-mode, buffered lookup of a resolution-unstable
    // spelling: answer from the pinned object (deterministic — dirfd-pinned
    // parent and fd-pinned object); anything else takes the original path.
    if(!hidden && buf && (flags & AT_SYMLINK_NOFOLLOW) == 0 && shdw_path_needs_verify(pathname)) {
        sub = shdw_stat64_substitute(dirfd, pathname, buf, flags);
    }
    if(sub != -2) {
        result = sub;
    } else {
        result = original_fstatat64(dirfd, pathname, hidden ? &trapbuf : buf, flags);
    }

    if(hidden) {
        errno = ENOENT;
        return -1;
    }
    // Bounded re-verification (fallback plus shape-holder — see
    // replaced_stat64 above).
    if(sub == -2 && result != -1 && !hidden &&
        shdw_at_post_verify(dirfd, pathname) != SHDW_POST_ADMIT) {
        if(buf) {
            memset(buf, 0, sizeof(shdw_stat64_t));
        }
        errno = ENOENT;
        return -1;
    }
    if(hidden) {
        errno = ENOENT;
        return -1;
    }

    if(result != -1 && buf && shdw_path_is_absolute(pathname)
       && shdw_path_under_system_bind_root(pathname)) {
        dev_t rootdev = shdw_rootfs_dev();
        if(rootdev != 0 && (dev_t)buf->st_dev != rootdev) {
            buf->st_dev = (typeof(buf->st_dev))rootdev;
        }
    }

    return result;
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

    if(ext && (flags & O_CREAT) && shdw_detector_c_write_path_denied(path)) {
        errno = ENOENT;
        return -1;
    }

    if(ext && shdw_path_is_main_bundle_exempt(path)) {
        if(flags & O_CREAT) {
            return original_open_dprotected_np(path, flags, class, dpflags, mode);
        }

        return original_open_dprotected_np(path, flags, class, dpflags);
    }

    if(ext && shdw_path_is_external_hidden_lexical(path)) {
        errno = ENOENT;
        return -1;
    }

    if(!ext || ![_shadow isCPathRestricted:path]) {
        int fd;
        if(flags & O_CREAT) {
            fd = original_open_dprotected_np(path, flags, class, dpflags, mode);
        } else {
            fd = original_open_dprotected_np(path, flags, class, dpflags);
        }
        // Verify-after-use (alias TOCTOU): the handed-out fd decides.
        if(fd >= 0 && ext && shdw_fd_names_hidden(fd)) {
            close(fd);
            errno = ENOENT;
            return -1;
        }
        return fd;
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

    if((flags & O_CREAT) && shdw_detector_c_write_path_denied(path)) {
        errno = ENOENT;
        return -1;
    }

    if(path && path[0] == '/') {
        if(shdw_path_is_main_bundle_exempt(path)) {
            if(flags & O_CREAT) {
                return original_openat_dprotected_np(dirfd, path, flags, class, dpflags, mode);
            }
            return original_openat_dprotected_np(dirfd, path, flags, class, dpflags);
        }
    } else if(path && path[0] != '\0') {
        char parent[PATH_MAX];
        shdw_dirfd_status_t st = shdw_resolve_dirfd_path(dirfd, path, parent, sizeof(parent));
        if(st == SHADW_DIRFD_OK) {
            char joined[PATH_MAX * 2];
            int n = snprintf(joined, sizeof(joined), "%s/%s", parent, path);
            if(n > 0 && n < (int)sizeof(joined) && shdw_path_is_main_bundle_exempt(joined)) {
                if(flags & O_CREAT) {
                    return original_openat_dprotected_np(dirfd, path, flags, class, dpflags, mode);
                }
                return original_openat_dprotected_np(dirfd, path, flags, class, dpflags);
            }
        }
    }

    if(shdw_at_path_denied(dirfd, path)) {
        return -1;
    }

    int dpdfd = -1;
    if(flags & O_CREAT) {
        dpdfd = original_openat_dprotected_np(dirfd, path, flags, class, dpflags, mode);
        if(dpdfd >= 0 && ext && shdw_fd_names_hidden(dpdfd)) {
            close(dpdfd);
            errno = ENOENT;
            return -1;
        }
        return dpdfd;
    }

    // Restricted-root paths: deny unconditionally for external callers
    if([_shadow isCPathRestricted:path] && (shdw_is_restricted_root(path) || ext)) {
        errno = ENOENT;
        return -1;
    }

    int dpdfd2 = original_openat_dprotected_np(dirfd, path, flags, class, dpflags);
    // Verify-after-use (alias TOCTOU): the handed-out fd decides.
    if(dpdfd2 >= 0 && ext && shdw_fd_names_hidden(dpdfd2)) {
        close(dpdfd2);
        errno = ENOENT;
        return -1;
    }
    return dpdfd2;
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

    if((flags & O_CREAT) && shdw_detector_c_write_path_denied(path)) {
        errno = ENOENT;
        return -1;
    }

    if(path && path[0] == '/') {
        if(shdw_path_is_main_bundle_exempt(path)) {
            if(flags & O_CREAT) {
                return original_openat_authenticated_np(dirfd, path, auth, flags, mode);
            }
            return original_openat_authenticated_np(dirfd, path, auth, flags);
        }
    } else if(path && path[0] != '\0') {
        char parent[PATH_MAX];
        shdw_dirfd_status_t st = shdw_resolve_dirfd_path(dirfd, path, parent, sizeof(parent));
        if(st == SHADW_DIRFD_OK) {
            char joined[PATH_MAX * 2];
            int n = snprintf(joined, sizeof(joined), "%s/%s", parent, path);
            if(n > 0 && n < (int)sizeof(joined) && shdw_path_is_main_bundle_exempt(joined)) {
                if(flags & O_CREAT) {
                    return original_openat_authenticated_np(dirfd, path, auth, flags, mode);
                }
                return original_openat_authenticated_np(dirfd, path, auth, flags);
            }
        }
    }

    if(shdw_at_path_denied(dirfd, path)) {
        return -1;
    }

    int aufd = -1;
    if(flags & O_CREAT) {
        aufd = original_openat_authenticated_np(dirfd, path, auth, flags, mode);
        if(aufd >= 0 && ext && shdw_fd_names_hidden(aufd)) {
            close(aufd);
            errno = ENOENT;
            return -1;
        }
        return aufd;
    }

    // Restricted-root paths: deny unconditionally for external callers
    if([_shadow isCPathRestricted:path] && (shdw_is_restricted_root(path) || ext)) {
        errno = ENOENT;
        return -1;
    }

    int aufd2 = original_openat_authenticated_np(dirfd, path, auth, flags);
    // Verify-after-use (alias TOCTOU): the handed-out fd decides.
    if(aufd2 >= 0 && ext && shdw_fd_names_hidden(aufd2)) {
        close(aufd2);
        errno = ENOENT;
        return -1;
    }
    return aufd2;
}

void shdw_universal_low_level_c(SHDWHookSession* hooks) {
    shdw_libc_install_group(hooks, SHADW_HOOK_GROUP_LOWLEVEL);
}
