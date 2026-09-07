#import "UniversalHooks.h"
#import "filters.h"
#import "../../policy/EnvironmentPolicy.h"
#import "../../policy/PathPolicy.h"
#import "../../policy/ProcessPolicy.h"

#import <string.h>
#import <stdlib.h>
#import <limits.h>
#import <sys/xattr.h>
#import <sys/resource.h>
#import <sys/attr.h>
#import <sys/snapshot.h>
#import <copyfile.h>
#import <sys/clonefile.h>
#import <glob.h>
#import <fts.h>
#import <ftw.h>

_Atomic BOOL shdw_path_rewrite_active = NO;

void shdw_path_rewrite_configure(BOOL enabled) {
    atomic_store_explicit(&shdw_path_rewrite_active, enabled, memory_order_release);
}

static int (*original_access)(const char* pathname, int mode);
// Jailbreak artifacts that are bind-mounted OVER real system locations
// (Dopamine's .fakelib) or written into system dirs, which a stock device
// never has. They can't go through the ruleset/RestrictionEngine path gate:
// systemhook.dylib in particular is the injection dylib every app (including
// the ones Shadow spawns) loads, so hiding it from Shadow's own internal
// dlopen/spawn breaks injection. Instead deny them ONLY here, only for external
// callers — a detector's access() sees ENOENT while Shadow's internal loader
// (isCallerExternal()==NO) still resolves them normally.
// Data-container leaf directories a jailbreak app leaves scattered under
// /var/mobile/Library (WebKit, HTTPStorages, Caches, Preferences, …) and
// /var/root. A probe enumerates <known-jb-bundle-id> under each of those dirs;
// a stock device never has these apps, so the residue is jailbreak evidence.
// The full container path is not a fixed string (many parent dirs), so match
// structurally: a /var/{mobile,root}/Library/ path whose final component begins
// with a known jailbreak app's bundle id.
static BOOL shdw_path_is_jb_app_container(const char* pathname) {
    if(!pathname) return NO;
    const char* rest = NULL;
    if(strncmp(pathname, "/var/mobile/Library/", 20) == 0) rest = pathname + 20;
    else if(strncmp(pathname, "/var/root/Library/", 18) == 0) rest = pathname + 18;
    if(!rest) return NO;

    const char* leaf = strrchr(rest, '/');
    leaf = leaf ? leaf + 1 : rest;  // final path component

    static const char* const jbAppIDs[] = {
        "com.xina.jailbreak", "com.opa334.Dopamine", "com.tigisoftware.Filza",
        "org.coolstar.SileoStore", "ws.hbang.Terminal", "xyz.willy.Zebra",
        NULL,
    };
    for(int i = 0; jbAppIDs[i]; i++) {
        size_t n = strlen(jbAppIDs[i]);
        if(strncmp(leaf, jbAppIDs[i], n) == 0) return YES;  // leaf is <id> or <id>.<suffix>
    }
    return NO;
}

static BOOL shdw_access_is_external_only_hidden(const char* pathname) {
    if(!pathname) return NO;
    static const char* const paths[] = {
        "/usr/lib/systemhook.dylib",
        "/usr/lib/sandbox.plist",
        "/var/log/launchdhook.log",
        NULL,
    };
    for(int i = 0; paths[i]; i++) {
        if(strcmp(pathname, paths[i]) == 0) return YES;
    }
    return shdw_path_is_jb_app_container(pathname);
}

static int replaced_access(const char* pathname, int mode) {
    if (shdw_is_fast_allowed_cpath(pathname)) return original_access(pathname, mode);
    int caller_errno = errno;
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "access", ext);

    if(ext && shdw_access_is_external_only_hidden(pathname)) {
        errno = ENOENT;
        return -1;
    }

    // Reuse this call's preflight verdict; concurrent filesystem or policy
    // changes are observed by later calls, not a second lookup here.
    BOOL restricted = NO;

    if(ext) {
        restricted = [_shadow isCPathRestricted:pathname];

        if(restricted && shdw_libc_try_rewrite(pathname)) {
            errno = caller_errno;
            return original_access(pathname, mode);   // natural ENOENT
        }
    }

    // The policy lookup can use libc internally. access(2) leaves errno
    // untouched on success, so do not leak an internal lookup's errno.
    errno = caller_errno;
    int result = original_access(pathname, mode);
    int result_errno = errno;

    // Restricted-root paths (e.g. /var/jb) are always jailbreak indicators —
    // deny unconditionally. Other restricted paths respect the external-caller
    // gate so Shadow's own code can still access them when needed.
    if(result != -1) {
        if(!ext) {
            restricted = [_shadow isCPathRestricted:pathname];
        }
        if(restricted && (shdw_is_restricted_root(pathname) || ext)) {
            errno = ENOENT;
            return -1;
        }
    }

    errno = result_errno;
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

// freadlink (iOS 16+ public in unistd.h; SYS_freadlink already present on
// the 15.6 floor): same policy as readlink, but the link is named by
// descriptor — resolve via F_GETPATH through the shared fresh fd policy
// (shdw_fd_path_restricted, PathPolicy.m) and fail open when the fd has no
// nameable path (tty/pipe/socket). Runtime-gated like mkfifoat/mknodat:
// skipped cleanly where libSystem lacks the export.
static ssize_t (*original_freadlink)(int fd, char* buf, size_t bufsize);
static ssize_t replaced_freadlink(int fd, char* buf, size_t bufsize) {
    if(!isCallerExternal()) {
        return original_freadlink(fd, buf, bufsize);
    }

    // buf NULL or bufsize 0: stock fails (EFAULT/EINVAL); replay before
    // classification so a malformed call keeps its stock error.
    if(buf == NULL || bufsize == 0) {
        return original_freadlink(fd, buf, bufsize);
    }

    if(shdw_fd_path_restricted(fd)) {
        errno = ENOENT;
        return -1;
    }

    // Read into a temp buffer first (same content check as readlink): a
    // link in a safe location can still name a restricted path.
    char content[PATH_MAX];
    ssize_t result = original_freadlink(fd, content, sizeof(content));

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

        if(copy_len > 0) {
            memcpy(buf, content, copy_len);
        }

        return (ssize_t) copy_len;
    }

    return result;
}

// Shared dirfd→path classification for the *at family, fresh fd/DIR
// resolution and the readlink target resolver live in policy/PathPolicy.m
// (also used by the raw-syscall surface in syscall.x — one resolver for every
// *at hook).

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
// removes hidden mounts, compacts the survivors in place and returns the
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

        int restricted = [_shadow isMountPathRestricted:rec->f_mntonname]
            || [_shadow isMountPathRestricted:rec->f_mntfromname];
        if(!shdw_mount_filter(rec->f_mntonname, rec->f_mntfromname,
            (uint32_t*) &rec->f_flags, statfsFlags, restricted)) {
            continue;  // hidden mount: removed, compacted away below
        }

        if(out != i) {
            buf[out] = buf[i];
        }

        out++;
    }

    return out;
}

static int (*original_getfsstat)(struct statfs* buf, int bufsize, int flags);

static int shdw_getfsstat_filtered_snapshot(int flags, int rawCount,
                                            struct statfs* destination, int destinationCapacity) {
    if(rawCount <= 0 || rawCount > INT_MAX / (int)sizeof(struct statfs)) {
        return rawCount;
    }
    int snapshotSize = rawCount * (int)sizeof(struct statfs);
    struct statfs* snapshot = malloc((size_t)snapshotSize);
    if(!snapshot) {
        return rawCount;
    }
    int result = original_getfsstat(snapshot, snapshotSize, flags);
    if(result > 0) {
        int written = result;
        int capacity = snapshotSize / (int)sizeof(struct statfs);
        if(capacity < written) {
            written = capacity;
        }
        result = shdw_filter_mounts(snapshot, written, YES);
        if(destination && destinationCapacity > 0) {
            int copied = result < destinationCapacity ? result : destinationCapacity;
            memcpy(destination, snapshot, (size_t)copied * sizeof(*snapshot));
            result = copied;
        }
    }
    free(snapshot);
    return result;
}

static int replaced_getfsstat(struct statfs* buf, int bufsize, int flags) {
    if(!isCallerExternal()) {
        return original_getfsstat(buf, bufsize, flags);
    }

    if(!buf && bufsize == 0) {
        int rawCount = original_getfsstat(NULL, 0, flags);
        return rawCount > 0 ? shdw_getfsstat_filtered_snapshot(flags, rawCount, NULL, 0) : rawCount;
    }

    if(buf && bufsize >= (int) sizeof(struct statfs)) {
        int capacity = bufsize / (int) sizeof(struct statfs);
        // A two-pass caller sized this buffer from our filtered count. Read a
        // full raw snapshot before filtering, otherwise the kernel truncates
        // the raw list before restricted records can be removed.
        int rawCount = original_getfsstat(NULL, 0, flags);
        return rawCount > 0 ? shdw_getfsstat_filtered_snapshot(flags, rawCount, buf, capacity) : rawCount;
    }

    return original_getfsstat(buf, bufsize, flags);
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

// A jailbreak bindfs (Dopamine's .fakelib) mounted OVER a stock system path
// leaves statfs(<stock path>) reporting a jailbreak f_mntfromname while
// f_mntonname stays the stock path itself. A probe that expects a stock system
// path to live on the root filesystem (f_mntonname == "/") flags the divergent
// mount point. For an external caller querying such a path, rewrite ONLY the
// two name fields the probe reads to the rootfs record; leave fsid/type/flags/
// geometry as the kernel reported them so nothing else the caller relies on
// changes. Returns YES if it reshaped. `pathname` is the query path (a stock
// location like /usr/lib), used to confirm the mount shadows a system dir.
static BOOL shdw_statfs_reshape_over_system(const char* pathname, struct statfs* buf) {
    if(!buf || !pathname) return NO;
    // Only stock system prefixes a jailbreak would bind over.
    static const char* const roots[] = { "/usr/lib", "/usr/libexec", "/System", NULL };
    BOOL underSystem = NO;
    for(int i = 0; roots[i]; i++) {
        size_t n = strlen(roots[i]);
        if(strncmp(pathname, roots[i], n) == 0 && (pathname[n] == '\0' || pathname[n] == '/')) {
            underSystem = YES;
            break;
        }
    }
    if(!underSystem) return NO;

    struct statfs root;
    if(original_statfs("/", &root) != 0) return NO;
    strlcpy(buf->f_mntonname, root.f_mntonname, sizeof(buf->f_mntonname));
    strlcpy(buf->f_mntfromname, root.f_mntfromname, sizeof(buf->f_mntfromname));
    return YES;
}

static BOOL shdw_mount_argument_restricted(const char* pathname) {
    if(!pathname || !pathname[0]) return NO;
    if(pathname[0] == '/') return [_shadow isMountPathRestricted:pathname];

    int savedErrno = errno;
    BOOL restricted = NO;
    SHADOW_INTERNAL_SCOPE {
        char cwd[PATH_MAX], joined[PATH_MAX * 2];
        // Avoid getcwd's metadata-scan fallback; only name the directory vnode.
        int fd = open(".", O_RDONLY | O_CLOEXEC);
        if(fd != -1) {
            if(fcntl(fd, F_GETPATH, cwd) != -1) {
                int n = snprintf(joined, sizeof(joined), "%s/%s", cwd, pathname);
                if(n > 0 && n < (int)sizeof(joined)) {
                    restricted = [_shadow isMountPathRestricted:joined];
                }
            }
            close(fd);
        }
    }
    errno = savedErrno;
    return restricted;
}

static BOOL shdw_mount_fd_restricted(int fd) {
    int savedErrno = errno;
    BOOL restricted = NO;
    SHADOW_INTERNAL_SCOPE {
        char pathname[PATH_MAX];
        if(fcntl(fd, F_GETPATH, pathname) != -1) {
            restricted = [_shadow isMountPathRestricted:pathname];
        }
    }
    errno = savedErrno;
    return restricted;
}

static int replaced_statfs(const char* pathname, struct statfs* buf) {
    if(!isCallerExternal()) {
        return original_statfs(pathname, buf);
    }

    // /private/preboot exists on stock iOS and is READ-ONLY there; a jailbreak
    // remounts it writable to stage its bootstrap, so a probe reading a cleared
    // MNT_RDONLY ("preboot writeable") treats it as evidence. The path is
    // otherwise restricted (denied) to hide the jailbreak's contents, but a
    // hard denial here zeroes the caller's buffer — which the writeable probe
    // ALSO reads as evidence (flags & MNT_RDONLY == 0). So special-case it
    // BEFORE the restriction deny: let the query succeed but force the stock
    // read-only flag. Its directory contents stay hidden via the path hooks.
    if(pathname && strcmp(pathname, "/private/preboot") == 0) {
        int result = original_statfs(pathname, buf);
        if(result == 0 && buf) {
            buf->f_flags |= MNT_RDONLY;
        }
        return result;
    }

    if(shdw_mount_argument_restricted(pathname)) {
        errno = ENOENT;
        return -1;
    }

    int result = original_statfs(pathname, buf);

    if(result == 0 && buf && shdw_filter_mounts(buf, 1, YES) == 0) {
        // The mount record itself is restricted (a jailbreak bindfs). If it
        // shadows a stock system path the caller legitimately queries, reshape
        // its name fields to the rootfs it covers; otherwise deny.
        if(!shdw_statfs_reshape_over_system(pathname, buf)) {
            errno = ENOENT;
            return -1;
        }
    }

    return result;
}

static int (*original_fstatfs)(int fd, struct statfs* buf);
static int replaced_fstatfs(int fd, struct statfs* buf) {
    if(!isCallerExternal()) {
        return original_fstatfs(fd, buf);
    }

    if(shdw_mount_fd_restricted(fd)) {
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

    if(shdw_mount_argument_restricted(pathname)) {
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

    if(shdw_mount_fd_restricted(fd)) {
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
    if (shdw_is_fast_allowed_cpath(pathname)) return original_stat(pathname, buf);
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "stat", ext);

    // Reuse this call's preflight verdict for both external-only checks.
    BOOL restricted = ext && [_shadow isCPathRestricted:pathname];

    if(restricted && shdw_libc_try_rewrite(pathname)) {
        return original_stat(pathname, buf);   // natural ENOENT
    }

    int result = original_stat(pathname, buf);

    if(result != -1 && restricted) {
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

    if(shdw_path_is_absolute(pathname)
       && [_shadow isCPathRestricted:pathname]
       && shdw_libc_try_rewrite(pathname)) {
        return original_fstatat(dirfd, pathname, buf, flags);   // natural ENOENT
    }

    if(shdw_at_path_denied(dirfd, pathname)) {
        return -1;
    }

    return original_fstatat(dirfd, pathname, buf, flags);
}

static int (*original_faccessat)(int dirfd, const char* pathname, int mode, int flags);
static int replaced_faccessat(int dirfd, const char* pathname, int mode, int flags) {
    int caller_errno = errno;
    BOOL ext = isCallerExternal();
    SHADOW_TRIP(pathname, "faccessat", ext);

    if(!ext) {
        return original_faccessat(dirfd, pathname, mode, flags);
    }

    // Relative operands must be classified against dirfd by shdw_at_path_denied.
    // The direct classification is only safe for absolute paths.
    BOOL restricted = shdw_path_is_absolute(pathname) && [_shadow isCPathRestricted:pathname];

    if(restricted && shdw_libc_try_rewrite(pathname)) {
        errno = caller_errno;
        return original_faccessat(dirfd, pathname, mode, flags);   // natural ENOENT
    }

    if(shdw_at_path_denied(dirfd, pathname)) {
        return -1;
    }

    errno = caller_errno;
    int result = original_faccessat(dirfd, pathname, mode, flags);
    int result_errno = errno;

    // Restricted-root paths: deny unconditionally for external callers
    if(result != -1) {
        if(restricted && (shdw_is_restricted_root(pathname) || ext)) {
            errno = ENOENT;
            return -1;
        }
    }

    errno = result_errno;
    return result;
}

// readdir/readdir_r filtering: fresh DIR* parent resolution (including the
// denied-vnode fail-closed fallback) lives in policy/PathPolicy.m; the per-entry
// child check runs here, external-caller-gated.

static int (*original_readdir_r)(DIR* dirp, struct dirent* entry, struct dirent** oresult);
static int replaced_readdir_r(DIR* dirp, struct dirent* entry, struct dirent** oresult) {
    if(!isCallerExternal()) {
        return original_readdir_r(dirp, entry, oresult);
    }

    BOOL denied = NO;
    NSDictionary* options = shdw_readdir_options(dirp, &denied);

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

    // Options are retained only when parent resolution succeeds.
    if(options) {
        CFRelease((__bridge CFDictionaryRef)options);
    }

    return result;
}

static struct dirent* (*original_readdir)(DIR* dirp);
static struct dirent* replaced_readdir(DIR* dirp) {
    if(!isCallerExternal()) {
        return original_readdir(dirp);
    }

    BOOL denied = NO;
    NSDictionary* options = shdw_readdir_options(dirp, &denied);

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

    // Options are retained only when parent resolution succeeds.
    if(options) {
        CFRelease((__bridge CFDictionaryRef)options);
    }

    return result;
}

// --- Phase 3: dir-enumeration conveniences. scandir/glob/fts/nftw all
// bottom out at readdir/getdirentries64 (already filtered), but they
// BUFFER results: a detector calling them sees unfiltered snapshots.
// So: post-success output filters reusing the same per-entry policy.
// scandir: compact namelist in place (caller's selector/compar already
// ran; survivors keep their selected+sorted order). Restricted parent
// itself → empty list, NOT an error (stock empty-directory shape).
// NOTE: freed with free(), NOT a per-entry free — compact in place, never
// free individual entries (the caller frees namelist[i] + namelist).
static BOOL shdw_scandir_entry_restricted(const char* dirpath, const char* name) {
    char joined[PATH_MAX * 2];
    int n = snprintf(joined, sizeof(joined), "%s/%s", dirpath, name);
    return n > 0 && n < (int)sizeof(joined) && [_shadow isCPathRestricted:joined];
}

static int shdw_scandir_filter(const char* dirpath, struct dirent*** namelist, int count) {
    if(count <= 0 || !namelist || !*namelist) {
        return count;
    }
    struct dirent** list = *namelist;
    int out = 0;
    for(int i = 0; i < count; i++) {
        @autoreleasepool {
            if(list[i] && !shdw_scandir_entry_restricted(dirpath, list[i]->d_name)) {
                list[out++] = list[i];
            } else if(list[i]) {
                free(list[i]);
            }
        }
    }
    return out;
}

static int (*original_scandir)(const char* dirname, struct dirent*** namelist,
    int (*selector)(const struct dirent*), int (*compar)(const struct dirent**, const struct dirent**));
static int replaced_scandir(const char* dirname, struct dirent*** namelist,
    int (*selector)(const struct dirent*), int (*compar)(const struct dirent**, const struct dirent**)) {
    if(!isCallerExternal()) {
        return original_scandir(dirname, namelist, selector, compar);
    }

    if(dirname && [_shadow isCPathRestricted:dirname]) {
        if(namelist) {
            *namelist = NULL;
        }
        return 0;  // stock empty-directory shape, not an error
    }

    int count = original_scandir(dirname, namelist, selector, compar);

    if(count > 0 && namelist && *namelist && dirname) {
        count = shdw_scandir_filter(dirname, namelist, count);
    }

    return count;
}

#ifdef __BLOCKS__
static int (*original_scandir_b)(const char* dirname, struct dirent*** namelist,
    int (^selector)(const struct dirent*), int (^compar)(const struct dirent**, const struct dirent**));
static int replaced_scandir_b(const char* dirname, struct dirent*** namelist,
    int (^selector)(const struct dirent*), int (^compar)(const struct dirent**, const struct dirent**)) {
    if(!isCallerExternal()) {
        return original_scandir_b(dirname, namelist, selector, compar);
    }

    if(dirname && [_shadow isCPathRestricted:dirname]) {
        if(namelist) {
            *namelist = NULL;
        }
        return 0;
    }

    int count = original_scandir_b(dirname, namelist, selector, compar);

    if(count > 0 && namelist && *namelist && dirname) {
        count = shdw_scandir_filter(dirname, namelist, count);
    }

    return count;
}
#endif

// glob: post-success filter of gl_pathv (pattern already expanded; each
// match is a concrete path). Compact in place, fix gl_pathc/gl_matchc,
// free removed strings. Emptied → GLOB_NOMATCH (stock contract when
// nothing matches and GLOB_NOCHECK is unset); with GLOB_NOCHECK the
// pattern itself is the single result — filter it too.
static BOOL shdw_glob_entry_restricted(const char* path) {
    return path && [_shadow isCPathRestricted:path];
}

static int shdw_glob_filter(glob_t* pglob) {
    if(!pglob || !pglob->gl_pathv) {
        return 0;
    }
    size_t out = pglob->gl_offs;  // reserved slots stay put
    for(size_t i = pglob->gl_offs; i < pglob->gl_offs + pglob->gl_pathc; i++) {
        @autoreleasepool {
            if(pglob->gl_pathv[i] && !shdw_glob_entry_restricted(pglob->gl_pathv[i])) {
                pglob->gl_pathv[out++] = pglob->gl_pathv[i];
            } else if(pglob->gl_pathv[i]) {
                free(pglob->gl_pathv[i]);
                pglob->gl_pathv[i] = NULL;
            }
        }
    }
    size_t kept = out - pglob->gl_offs;
    pglob->gl_pathv[out] = NULL;
    pglob->gl_pathc = kept;
    pglob->gl_matchc = (int)kept;
    return (int)kept;
}

static int (*original_glob)(const char* pattern, int flags, int (*errfunc)(const char*, int), glob_t* pglob);
static int replaced_glob(const char* pattern, int flags, int (*errfunc)(const char*, int), glob_t* pglob) {
    if(!isCallerExternal()) {
        return original_glob(pattern, flags, errfunc, pglob);
    }

    int ret = original_glob(pattern, flags, errfunc, pglob);

    if(ret == 0 && pglob && shdw_glob_filter(pglob) == 0) {
        return GLOB_NOMATCH;
    }

    return ret;
}

static void (*original_globfree)(glob_t* pglob);
static void replaced_globfree(glob_t* pglob) {
    // Pass-through: replaced_glob compacts WITHOUT reallocating (same
    // buffer, fewer entries, NULL-terminated), so the stock globfree
    // frees exactly what it always freed. Hooked only for dlsym-policy
    // agreement (GOT-vs-dlsym comparison).
    return original_globfree(pglob);
}

#ifdef __BLOCKS__
static int (*original_glob_b)(const char* pattern, int flags, int (^errblk)(const char*, int), glob_t* pglob);
static int replaced_glob_b(const char* pattern, int flags, int (^errblk)(const char*, int), glob_t* pglob) {
    if(!isCallerExternal()) {
        return original_glob_b(pattern, flags, errblk, pglob);
    }

    int ret = original_glob_b(pattern, flags, errblk, pglob);

    if(ret == 0 && pglob && shdw_glob_filter(pglob) == 0) {
        return GLOB_NOMATCH;
    }

    return ret;
}
#endif

// fts: wrap the traversal at fts_read/fts_children — skip restricted
// NODES by advancing to the next sibling (fts_link), never by failing
// the walk. fts_open paths are pre-screened (restricted ROOT fails with
// ENOENT like opendir); children of a restricted dir never surface
// because the parent node itself is skipped first.
static BOOL shdw_fts_entry_restricted(FTSENT* ent) {
    if(!ent || !ent->fts_accpath) {
        return NO;
    }
    return [_shadow isCPathRestricted:ent->fts_accpath];
}

static FTS* (*original_fts_open)(char* const* path_argv, int options, int (*compar)(const FTSENT**, const FTSENT**));
static FTS* replaced_fts_open(char* const* path_argv, int options, int (*compar)(const FTSENT**, const FTSENT**)) {
    if(!isCallerExternal()) {
        return original_fts_open(path_argv, options, compar);
    }

    // Pre-screen roots: any restricted root fails the open (stock
    // opendir-on-restricted shape). Mixed roots: let it open, filter
    // per-node below.
    if(path_argv) {
        BOOL allRestricted = YES;
        BOOL anyPath = NO;
        for(char* const* p = path_argv; *p; p++) {
            anyPath = YES;
            if(![_shadow isCPathRestricted:*p]) {
                allRestricted = NO;
                break;
            }
        }
        if(anyPath && allRestricted) {
            errno = ENOENT;
            return NULL;
        }
    }

    return original_fts_open(path_argv, options, compar);
}

static FTSENT* (*original_fts_read)(FTS* ftsp);
static FTSENT* replaced_fts_read(FTS* ftsp) {
    if(!isCallerExternal()) {
        return original_fts_read(ftsp);
    }

    FTSENT* ent;
    while((ent = original_fts_read(ftsp)) != NULL) {
        @autoreleasepool {
            if(!shdw_fts_entry_restricted(ent)) {
                break;
            }
        }
        // Restricted node: skip its entire subtree by telling fts to not
        // descend, then continue to the next entry.
        if(ent->fts_info == FTS_D) {
            fts_set(ftsp, ent, FTS_SKIP);
        }
    }
    return ent;
}

static FTSENT* (*original_fts_children)(FTS* ftsp, int instr);
static FTSENT* replaced_fts_children(FTS* ftsp, int instr) {
    if(!isCallerExternal()) {
        return original_fts_children(ftsp, instr);
    }

    FTSENT* head = original_fts_children(ftsp, instr);
    // Unlink restricted nodes from the sibling chain in place (fts_link).
    // Head may itself be restricted — advance past it.
    FTSENT** link = &head;
    while(*link) {
        @autoreleasepool {
            if(!shdw_fts_entry_restricted(*link)) {
                link = &(*link)->fts_link;
            } else {
                *link = (*link)->fts_link;
            }
        }
    }
    return head;
}

// ftw/nftw: wrap the user callback — restricted paths are silently
// skipped (return 0, continue walk), never reported. The callback runs
// on our frame, so isCallerExternal() is read HERE (hook frame), not
// inside the trampoline.
static _Thread_local BOOL shdw_ftw_filtering = NO;
static _Thread_local int (*shdw_ftw_userfn)(const char*, const struct stat*, int) = NULL;
static _Thread_local int (*shdw_nftw_userfn)(const char*, const struct stat*, int, struct FTW*) = NULL;

static int shdw_ftw_trampoline(const char* path, const struct stat* sb, int typeflag) {
    if(shdw_ftw_filtering && path && [_shadow isCPathRestricted:path]) {
        return 0;  // skip: continue walk without calling user fn
    }
    return shdw_ftw_userfn ? shdw_ftw_userfn(path, sb, typeflag) : 0;
}

static int shdw_nftw_trampoline(const char* path, const struct stat* sb, int typeflag, struct FTW* ftwbuf) {
    if(shdw_ftw_filtering && path && [_shadow isCPathRestricted:path]) {
        // Skip restricted nodes without aborting the walk. nftw has no
        // FTW_ACTIONRETVAL/FTW_SKIP_SUBTREE on this SDK (plain BSD ftw.h:
        // FTW_F/D/DNR/DP/NS/SL/SLN only), so returning 0 continues the
        // walk — the restricted dir's CHILDREN are each classified on
        // their own callback and skipped the same way. No abort, no leak.
        (void)ftwbuf;
        (void)typeflag;
        return 0;
    }
    return shdw_nftw_userfn ? shdw_nftw_userfn(path, sb, typeflag, ftwbuf) : 0;
}

static int (*original_ftw)(const char* path, int (*fn)(const char*, const struct stat*, int), int nopenfd);
static int replaced_ftw(const char* path, int (*fn)(const char*, const struct stat*, int), int nopenfd) {
    if(!isCallerExternal()) {
        return original_ftw(path, fn, nopenfd);
    }

    if(path && [_shadow isCPathRestricted:path]) {
        errno = ENOENT;
        return -1;
    }

    shdw_ftw_filtering = YES;
    shdw_ftw_userfn = fn;
    int ret = original_ftw(path, shdw_ftw_trampoline, nopenfd);
    shdw_ftw_filtering = NO;
    shdw_ftw_userfn = NULL;
    return ret;
}

static int (*original_nftw)(const char* path, int (*fn)(const char*, const struct stat*, int, struct FTW*), int nopenfd, int flags);
static int replaced_nftw(const char* path, int (*fn)(const char*, const struct stat*, int, struct FTW*), int nopenfd, int flags) {
    if(!isCallerExternal()) {
        return original_nftw(path, fn, nopenfd, flags);
    }

    if(path && [_shadow isCPathRestricted:path]) {
        errno = ENOENT;
        return -1;
    }

    shdw_ftw_filtering = YES;
    shdw_nftw_userfn = fn;
    int ret = original_nftw(path, shdw_nftw_trampoline, nopenfd, flags);
    shdw_ftw_filtering = NO;
    shdw_nftw_userfn = NULL;
    return ret;
}

// --- Phase 4: CFPreferences (same suite gate as NSUserDefaults).
// NSUserDefaults sits ON TOP of CFPreferences: a detector calling the CF
// layer directly bypasses the NSUserDefaults hooks entirely
// (AppEnvironment.x shadowhook_NSUserDefaults). The suite predicate is the
// AppEnvironment.x single source (shdw_nsuserdefaults_suite_restricted),
// declared in hooks.h — no duplicated tables here.
// Stock shapes: reads → nil/empty, sync → false.
// Writes pass through — a denied write would itself be observable, and
// nobody legitimate reads a restricted suite.
static BOOL shdw_cf_suite_restricted(CFStringRef applicationID) {
    if(!applicationID) {
        return NO;
    }

    return shdw_nsuserdefaults_suite_restricted((__bridge NSString*)applicationID);
}

static CFPropertyListRef (*original_CFPreferencesCopyAppValue)(CFStringRef key, CFStringRef applicationID);
static CFPropertyListRef replaced_CFPreferencesCopyAppValue(CFStringRef key, CFStringRef applicationID) {
    if(isCallerExternal() && shdw_cf_suite_restricted(applicationID)) {
        shdw_detector_detected("nsuserdefaults");
        return NULL;
    }
    return original_CFPreferencesCopyAppValue(key, applicationID);
}

static CFPropertyListRef (*original_CFPreferencesCopyValue)(CFStringRef key, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName);
static CFPropertyListRef replaced_CFPreferencesCopyValue(CFStringRef key, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName) {
    if(isCallerExternal() && shdw_cf_suite_restricted(applicationID)) {
        shdw_detector_detected("nsuserdefaults");
        return NULL;
    }
    return original_CFPreferencesCopyValue(key, applicationID, userName, hostName);
}

static CFDictionaryRef (*original_CFPreferencesCopyMultiple)(CFArrayRef keysToFetch, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName);
static CFDictionaryRef replaced_CFPreferencesCopyMultiple(CFArrayRef keysToFetch, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName) {
    if(isCallerExternal() && shdw_cf_suite_restricted(applicationID)) {
        shdw_detector_detected("nsuserdefaults");
        // Stock empty-dict shape: +1 dictionary the caller owns (Copy
        // rule); never a shared singleton a caller could mutate.
        return CFDictionaryCreate(NULL, NULL, NULL, 0, NULL, NULL);
    }
    return original_CFPreferencesCopyMultiple(keysToFetch, applicationID, userName, hostName);
}

static Boolean (*original_CFPreferencesAppSynchronize)(CFStringRef applicationID);
static Boolean replaced_CFPreferencesAppSynchronize(CFStringRef applicationID) {
    if(isCallerExternal() && shdw_cf_suite_restricted(applicationID)) {
        return false;
    }
    return original_CFPreferencesAppSynchronize(applicationID);
}

static FILE* (*original_fopen)(const char* pathname, const char* mode);
static FILE* replaced_fopen(const char* pathname, const char* mode) {
    if (shdw_is_fast_allowed_cpath(pathname)) return original_fopen(pathname, mode);
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
    if(!isCallerExternal() || !(shdw_detector_c_write_path_denied(path2) ||
       [_shadow isCPathRestricted:path1] || [_shadow isCPathRestricted:path2])) {
        return original_link(path1, path2);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_rename)(const char* old, const char* new);
static int replaced_rename(const char* old, const char* new) {
    if(!isCallerExternal() || !(shdw_detector_c_write_path_denied(new) ||
       [_shadow isCPathRestricted:old] || [_shadow isCPathRestricted:new])) {
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

    if(path2 && path2[0] == '/' && shdw_detector_c_write_path_denied(path2)) {
        errno = ENOENT;
        return -1;
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

    if(to && to[0] == '/' && shdw_detector_c_write_path_denied(to)) {
        errno = ENOENT;
        return -1;
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

// iOS 16+ *at creation variants. These are runtime-resolved below so the
// same binary still runs on the iOS 15 rootless floor.
static int (*original_mkfifoat)(int dirfd, const char* path, mode_t mode);
static int replaced_mkfifoat(int dirfd, const char* path, mode_t mode) {
    if(!isCallerExternal()) {
        return original_mkfifoat(dirfd, path, mode);
    }

    if(shdw_at_path_denied(dirfd, path)) {
        return -1;
    }

    return original_mkfifoat(dirfd, path, mode);
}

static int (*original_mknodat)(int dirfd, const char* path, mode_t mode, dev_t dev);
static int replaced_mknodat(int dirfd, const char* path, mode_t mode, dev_t dev) {
    if(!isCallerExternal()) {
        return original_mknodat(dirfd, path, mode, dev);
    }

    if(shdw_at_path_denied(dirfd, path)) {
        return -1;
    }

    return original_mknodat(dirfd, path, mode, dev);
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

// --- Plain-path metadata mutators (Phase 1 gaps). One (path) or
// (path, id/id) or (path, value...) shape, single-path policy, ENOENT on
// denial — same contract as replaced_rmdir/pathconf above. fd variants use
// shdw_fd_path_restricted + EBADF like replaced_futimes above.
static int (*original_mkdir)(const char* pathname, mode_t mode);
static int replaced_mkdir(const char* pathname, mode_t mode) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_mkdir(pathname, mode);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_chmod)(const char* pathname, mode_t mode);
static int replaced_chmod(const char* pathname, mode_t mode) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_chmod(pathname, mode);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_lchmod)(const char* pathname, mode_t mode);
static int replaced_lchmod(const char* pathname, mode_t mode) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_lchmod(pathname, mode);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_fchmod)(int fd, mode_t mode);
static int replaced_fchmod(int fd, mode_t mode) {
    if(!isCallerExternal()) {
        return original_fchmod(fd, mode);
    }

    if(shdw_fd_path_restricted(fd)) {
        errno = EBADF;
        return -1;
    }

    return original_fchmod(fd, mode);
}

static int (*original_chown)(const char* pathname, uid_t owner, gid_t group);
static int replaced_chown(const char* pathname, uid_t owner, gid_t group) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_chown(pathname, owner, group);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_lchown)(const char* pathname, uid_t owner, gid_t group);
static int replaced_lchown(const char* pathname, uid_t owner, gid_t group) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_lchown(pathname, owner, group);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_fchown)(int fd, uid_t owner, gid_t group);
static int replaced_fchown(int fd, uid_t owner, gid_t group) {
    if(!isCallerExternal()) {
        return original_fchown(fd, owner, group);
    }

    if(shdw_fd_path_restricted(fd)) {
        errno = EBADF;
        return -1;
    }

    return original_fchown(fd, owner, group);
}

static int (*original_mknod)(const char* pathname, mode_t mode, dev_t dev);
static int replaced_mknod(const char* pathname, mode_t mode, dev_t dev) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_mknod(pathname, mode, dev);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_mkfifo)(const char* pathname, mode_t mode);
static int replaced_mkfifo(const char* pathname, mode_t mode) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_mkfifo(pathname, mode);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_truncate)(const char* pathname, off_t length);
static int replaced_truncate(const char* pathname, off_t length) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_truncate(pathname, length);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_ftruncate)(int fd, off_t length);
static int replaced_ftruncate(int fd, off_t length) {
    if(!isCallerExternal()) {
        return original_ftruncate(fd, length);
    }

    if(shdw_fd_path_restricted(fd)) {
        errno = EBADF;
        return -1;
    }

    return original_ftruncate(fd, length);
}

static int (*original_chflags)(const char* pathname, __uint32_t flags);
static int replaced_chflags(const char* pathname, __uint32_t flags) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_chflags(pathname, flags);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_lchflags)(const char* pathname, __uint32_t flags);
static int replaced_lchflags(const char* pathname, __uint32_t flags) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_lchflags(pathname, flags);
    }

    errno = ENOENT;
    return -1;
}

static int (*original_fchflags)(int fd, __uint32_t flags);
static int replaced_fchflags(int fd, __uint32_t flags) {
    if(!isCallerExternal()) {
        return original_fchflags(fd, flags);
    }

    if(shdw_fd_path_restricted(fd)) {
        errno = EBADF;
        return -1;
    }

    return original_fchflags(fd, flags);
}

static int (*original_futimens)(int fd, const struct timespec times[2]);
static int replaced_futimens(int fd, const struct timespec times[2]) {
    if(!isCallerExternal()) {
        return original_futimens(fd, times);
    }

    if(shdw_fd_path_restricted(fd)) {
        errno = EBADF;
        return -1;
    }

    return original_futimens(fd, times);
}

static int (*original_lutimes)(const char* pathname, const struct timeval times[2]);
static int replaced_lutimes(const char* pathname, const struct timeval times[2]) {
    if(!isCallerExternal() || ![_shadow isCPathRestricted:pathname]) {
        return original_lutimes(pathname, times);
    }

    errno = ENOENT;
    return -1;
}

// --- Phase 2: copy/clone (dual-path + fd-state coverage). A detector can
// exfiltrate a restricted file to a readable location (copyfile/clonefile
// src→dst), or materialize restricted CONTENT at a readable path
// (fcopyfile/fclonefileat on fds resolved via COPYFILE_STATE fds or
// dirfd). So: classify BOTH endpoints, and resolve fd endpoints through
// the COPYFILE_STATE (copyfile_state_get SRC/DST_FILENAME or _FD) or the
// dirfd — never just the string args.

// Resolves one copyfile_state endpoint to a restricted verdict: prefers
// the FILENAME string when set (exact path), else the FD via fresh F_GETPATH.
// Fail open (NO) when neither is set — an unset endpoint can't name a
// restricted path.
static BOOL shdw_copyfile_state_endpoint_restricted(copyfile_state_t state, uint32_t fnFlag, uint32_t fdFlag) {
    if(state) {
        const char* fn = NULL;
        if(copyfile_state_get(state, fnFlag, (void*)&fn) == 0 && fn && fn[0]) {
            if([_shadow isCPathRestricted:fn]) {
                return YES;
            }
        } else {
            int fd = -1;
            if(copyfile_state_get(state, fdFlag, &fd) == 0 && fd >= 0) {
                if(shdw_fd_path_restricted(fd)) {
                    return YES;
                }
            }
        }
    }
    return NO;
}

static int (*original_copyfile)(const char* from, const char* to, copyfile_state_t state, copyfile_flags_t flags);
static int replaced_copyfile(const char* from, const char* to, copyfile_state_t state, copyfile_flags_t flags) {
    if(!isCallerExternal()) {
        return original_copyfile(from, to, state, flags);
    }

    // String args first (cheap, no state deref); then the state endpoints,
    // which may name DIFFERENT paths than the strings (COPYFILE_STATE fds
    // override when set).
    if((from && [_shadow isCPathRestricted:from]) ||
       (to && [_shadow isCPathRestricted:to]) ||
       shdw_copyfile_state_endpoint_restricted(state, COPYFILE_STATE_SRC_FILENAME, COPYFILE_STATE_SRC_FD) ||
       shdw_copyfile_state_endpoint_restricted(state, COPYFILE_STATE_DST_FILENAME, COPYFILE_STATE_DST_FD)) {
        errno = ENOENT;
        return -1;
    }

    return original_copyfile(from, to, state, flags);
}

static int (*original_fcopyfile)(int from_fd, int to_fd, copyfile_state_t state, copyfile_flags_t flags);
static int replaced_fcopyfile(int from_fd, int to_fd, copyfile_state_t state, copyfile_flags_t flags) {
    if(!isCallerExternal()) {
        return original_fcopyfile(from_fd, to_fd, state, flags);
    }

    if(shdw_fd_path_restricted(from_fd) || shdw_fd_path_restricted(to_fd) ||
       shdw_copyfile_state_endpoint_restricted(state, COPYFILE_STATE_SRC_FILENAME, COPYFILE_STATE_SRC_FD) ||
       shdw_copyfile_state_endpoint_restricted(state, COPYFILE_STATE_DST_FILENAME, COPYFILE_STATE_DST_FD)) {
        errno = EBADF;
        return -1;
    }

    return original_fcopyfile(from_fd, to_fd, state, flags);
}

static int (*original_clonefile)(const char* src, const char* dst, uint32_t flags);
static int replaced_clonefile(const char* src, const char* dst, uint32_t flags) {
    if(!isCallerExternal()) {
        return original_clonefile(src, dst, flags);
    }

    if((src && [_shadow isCPathRestricted:src]) ||
       (dst && [_shadow isCPathRestricted:dst])) {
        errno = ENOENT;
        return -1;
    }

    return original_clonefile(src, dst, flags);
}

static int (*original_clonefileat)(int src_dirfd, const char* src, int dst_dirfd, const char* dst, uint32_t flags);
static int replaced_clonefileat(int src_dirfd, const char* src, int dst_dirfd, const char* dst, uint32_t flags) {
    if(!isCallerExternal()) {
        return original_clonefileat(src_dirfd, src, dst_dirfd, dst, flags);
    }

    // Both path arguments are resolved against their own dirfd (linkat pattern).
    if(shdw_at_path_denied(src_dirfd, src) || shdw_at_path_denied(dst_dirfd, dst)) {
        return -1;
    }

    return original_clonefileat(src_dirfd, src, dst_dirfd, dst, flags);
}

static int (*original_fclonefileat)(int srcfd, int dst_dirfd, const char* dst, uint32_t flags);
static int replaced_fclonefileat(int srcfd, int dst_dirfd, const char* dst, uint32_t flags) {
    if(!isCallerExternal()) {
        return original_fclonefileat(srcfd, dst_dirfd, dst, flags);
    }

    if(shdw_fd_path_restricted(srcfd)) {
        errno = EBADF;
        return -1;
    }

    if(shdw_at_path_denied(dst_dirfd, dst)) {
        return -1;
    }

    return original_fclonefileat(srcfd, dst_dirfd, dst, flags);
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
// Group semantics, byte-identical to the old per-group code: utimensat is
// installed but excluded from verify (it was iOS-11-gated with an @available
// check; dlsym is that check now); the optional runtime-resolved families are
// installed, never verified.
typedef struct {
    const char* symbol;     // dlsym name (C identifier, unmangled)
    void* replacement;      // the hook replacement
    void** original;        // original-slot out pointer (NULL = TU-local cell, see below)
    uint32_t installGroups; // bitmask: hooked when one of these groups installs
    uint32_t verifyGroups;  // bitmask: NULL original is a verify failure here (required)
} shdw_hook_desc_t;

#define LIBC   SHADW_HOOK_GROUP_LIBC
#define ENVVAR SHADW_HOOK_GROUP_ENVVAR
#define LOW    SHADW_HOOK_GROUP_LOWLEVEL
#define ANTIDBG SHADW_HOOK_GROUP_ANTIDEBUG
#define METADATA SHADW_HOOK_GROUP_FEATURE_METADATA

static const shdw_hook_desc_t shdw_libc_hooks[] = {
    // The narrow metadata feature owns these overlap symbols through the rebind lane.
    // Installing them again through libc would replace their predecessor with
    // an already-live entry hook and recurse.
    { "access",                 (void*)&replaced_access,                   (void**)&original_access,                   METADATA, METADATA },
    { "chdir",                  (void*)&replaced_chdir,                    (void**)&original_chdir,                    LIBC,   LIBC },
    { "chroot",                 (void*)&replaced_chroot,                   (void**)&original_chroot,                   LIBC,   LIBC },
    { "creat",                  (void*)&replaced_creat,                    (void**)&original_creat,                    LIBC,   LIBC },
    { "statfs",                 (void*)&replaced_statfs,                   (void**)&original_statfs,                   LIBC,   LIBC },
    { "fstatfs",                (void*)&replaced_fstatfs,                  (void**)&original_fstatfs,                  LIBC,   LIBC },
    { "statvfs",                (void*)&replaced_statvfs,                  (void**)&original_statvfs,                  LIBC,   LIBC },
    { "fstatvfs",               (void*)&replaced_fstatvfs,                 (void**)&original_fstatvfs,                 LIBC,   LIBC },
    { "stat",                   (void*)&replaced_stat,                     (void**)&original_stat,                     METADATA, METADATA },
    { "lstat",                  (void*)&replaced_lstat,                    (void**)&original_lstat,                    METADATA, METADATA },
    { "faccessat",              (void*)&replaced_faccessat,                (void**)&original_faccessat,                METADATA, METADATA },
    { "readdir_r",              (void*)&replaced_readdir_r,                (void**)&original_readdir_r,                LIBC,   LIBC },
    { "readdir",                (void*)&replaced_readdir,                  (void**)&original_readdir,                  LIBC,   LIBC },
    { "fopen",                  (void*)&replaced_fopen,                    (void**)&original_fopen,                    METADATA, METADATA },
    { "freopen",                (void*)&replaced_freopen,                  (void**)&original_freopen,                  LIBC,   LIBC },
    { "realpath",               (void*)&replaced_realpath,                 (void**)&original_realpath,                 LIBC,   LIBC },
    { "readlink",               (void*)&replaced_readlink,                 (void**)&original_readlink,                 METADATA, METADATA },
    { "readlinkat",             (void*)&replaced_readlinkat,               (void**)&original_readlinkat,               METADATA, METADATA },
    { "freadlink",              (void*)&replaced_freadlink,                (void**)&original_freadlink,                LIBC,   0 },   // iOS 16+ export; SYS_freadlink on 15.6 floor
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
    // Phase 1 mutators: plain-path deny ENOENT (rmdir contract), fd deny
    // EBADF (futimes contract). All present since the 15.6 floor.
    { "mkdir",                  (void*)&replaced_mkdir,                    (void**)&original_mkdir,                    LIBC,   LIBC },
    { "chmod",                  (void*)&replaced_chmod,                    (void**)&original_chmod,                    LIBC,   LIBC },
    { "lchmod",                 (void*)&replaced_lchmod,                   (void**)&original_lchmod,                   LIBC,   LIBC },
    { "fchmod",                 (void*)&replaced_fchmod,                   (void**)&original_fchmod,                   LIBC,   LIBC },
    { "chown",                  (void*)&replaced_chown,                    (void**)&original_chown,                    LIBC,   LIBC },
    { "lchown",                 (void*)&replaced_lchown,                   (void**)&original_lchown,                   LIBC,   LIBC },
    { "fchown",                 (void*)&replaced_fchown,                   (void**)&original_fchown,                   LIBC,   LIBC },
    { "mknod",                  (void*)&replaced_mknod,                    (void**)&original_mknod,                    LIBC,   LIBC },
    { "mkfifo",                 (void*)&replaced_mkfifo,                   (void**)&original_mkfifo,                   LIBC,   LIBC },
    { "truncate",               (void*)&replaced_truncate,                 (void**)&original_truncate,                 LIBC,   LIBC },
    { "ftruncate",              (void*)&replaced_ftruncate,                (void**)&original_ftruncate,               LIBC,   LIBC },
    { "chflags",                (void*)&replaced_chflags,                  (void**)&original_chflags,                 LIBC,   LIBC },
    { "lchflags",               (void*)&replaced_lchflags,                 (void**)&original_lchflags,                LIBC,   LIBC },
    { "fchflags",               (void*)&replaced_fchflags,                 (void**)&original_fchflags,                LIBC,   LIBC },
    { "futimens",               (void*)&replaced_futimens,                 (void**)&original_futimens,                LIBC,   LIBC },
    { "lutimes",                (void*)&replaced_lutimes,                  (void**)&original_lutimes,                 LIBC,   LIBC },
    // Phase 2 copy/clone: dual-endpoint (src+dst) classification. Present
    // since the 15.6 floor; fd/state resolution fails open.
    { "copyfile",               (void*)&replaced_copyfile,                (void**)&original_copyfile,               LIBC,   LIBC },
    { "fcopyfile",              (void*)&replaced_fcopyfile,               (void**)&original_fcopyfile,              LIBC,   LIBC },
    { "clonefile",              (void*)&replaced_clonefile,               (void**)&original_clonefile,              LIBC,   LIBC },
    { "clonefileat",            (void*)&replaced_clonefileat,             (void**)&original_clonefileat,            LIBC,   LIBC },
    { "fclonefileat",           (void*)&replaced_fclonefileat,            (void**)&original_fclonefileat,           LIBC,   LIBC },
    // Phase 3 dir-enum conveniences: post-success output filters over the
    // already-filtered readdir/getdirentries64 substrate. globfree is a
    // pass-through for dlsym-policy agreement (no realloc in the filter).
    { "scandir",                (void*)&replaced_scandir,                 (void**)&original_scandir,                LIBC,   LIBC },
#ifdef __BLOCKS__
    { "scandir_b",              (void*)&replaced_scandir_b,               (void**)&original_scandir_b,              LIBC,   0 },
#endif
    { "glob",                   (void*)&replaced_glob,                    (void**)&original_glob,                   LIBC,   LIBC },
    { "globfree",               (void*)&replaced_globfree,                (void**)&original_globfree,               LIBC,   0 },
#ifdef __BLOCKS__
    { "glob_b",                 (void*)&replaced_glob_b,                  (void**)&original_glob_b,                 LIBC,   0 },
#endif
    { "fts_open",               (void*)&replaced_fts_open,                (void**)&original_fts_open,               LIBC,   LIBC },
    { "fts_read",               (void*)&replaced_fts_read,                (void**)&original_fts_read,               LIBC,   LIBC },
    { "fts_children",           (void*)&replaced_fts_children,            (void**)&original_fts_children,           LIBC,   0 },
    { "ftw",                    (void*)&replaced_ftw,                     (void**)&original_ftw,                    LIBC,   LIBC },
    { "nftw",                   (void*)&replaced_nftw,                    (void**)&original_nftw,                   LIBC,   LIBC },
    // Phase 4 CFPreferences: same suite gate as NSUserDefaults (predicate
    // lives in AppEnvironment.x). Reads denied, sync fails closed, writes
    // pass through (unobservable).
    { "CFPreferencesCopyAppValue", (void*)&replaced_CFPreferencesCopyAppValue, (void**)&original_CFPreferencesCopyAppValue, LIBC, LIBC },
    { "CFPreferencesCopyValue", (void*)&replaced_CFPreferencesCopyValue, (void**)&original_CFPreferencesCopyValue, LIBC, LIBC },
    { "CFPreferencesCopyMultiple", (void*)&replaced_CFPreferencesCopyMultiple, (void**)&original_CFPreferencesCopyMultiple, LIBC, LIBC },
    { "CFPreferencesAppSynchronize", (void*)&replaced_CFPreferencesAppSynchronize, (void**)&original_CFPreferencesAppSynchronize, LIBC, 0 },
    { "getfsstat",              (void*)&replaced_getfsstat,                (void**)&original_getfsstat,                LIBC,   LIBC },
    { "fstat",                  (void*)&replaced_fstat,                    (void**)&original_fstat,                    LIBC,   LIBC },
    { "fstatat",                (void*)&replaced_fstatat,                  (void**)&original_fstatat,                  LIBC,   LIBC },
    // installed-only (verification excluded, matching the old code's exempt lists)
    { "utimensat",              (void*)&replaced_utimensat,                (void**)&original_utimensat,                LIBC,   0 },   // iOS 11+ gate: dlsym is the availability check
    { "getmntinfo_r_np",        (void*)&shdw_replaced_getmntinfo_r_np,     (void**)&original_getmntinfo_r_np,          LIBC,   0 },   // iOS 16+ export
    { "mkfifoat",               (void*)&replaced_mkfifoat,                 (void**)&original_mkfifoat,                 LIBC,   0 },   // iOS 16+ export
    { "mknodat",                (void*)&replaced_mknodat,                  (void**)&original_mknodat,                  LIBC,   0 },   // iOS 16+ export

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

    // antidebugging group
    { "ptrace",                 (void*)&replaced_ptrace,                   (void**)&original_ptrace,                   ANTIDBG,  ANTIDBG },
    { "sysctl",                 (void*)&replaced_sysctl,                   (void**)&original_sysctl,                   ANTIDBG,  ANTIDBG },
    { "getppid",                (void*)&replaced_getppid,                  (void**)&original_getppid,                  ANTIDBG,  ANTIDBG },
    { "getuid",                 (void*)&replaced_getuid,                   (void**)&original_getuid,                   ANTIDBG,  ANTIDBG },
    { "geteuid",                (void*)&replaced_geteuid,                 (void**)&original_geteuid,                 ANTIDBG,  ANTIDBG },
    { "getgid",                 (void*)&replaced_getgid,                   (void**)&original_getgid,                   ANTIDBG,  ANTIDBG },
    { "getegid",                (void*)&replaced_getegid,                 (void**)&original_getegid,                 ANTIDBG,  ANTIDBG },
    { "issetugid",              (void*)&replaced_issetugid,                (void**)&original_issetugid,                ANTIDBG,  ANTIDBG },
    { "getrusage",              (void*)&replaced_getrusage,                (void**)&original_getrusage,                ANTIDBG,  ANTIDBG },
    // wait family: rusage/siginfo out-param zeroing (matches getrusage
    // above). waitpid is a pure pass-through for dlsym-policy agreement
    // (no resource out-param to sanitize); installed, never verified.
    // wait4/wait3/waitid have no original cell (outOldPtr NULL): only the
    // out-param is sanitized post-success, never forwarded — same pattern
    // as the execle/execlp/execl/execv sandbox rows.
    { "wait4",                  (void*)&replaced_wait4,                    NULL,                                         ANTIDBG,  0 },
    { "waitpid",                (void*)&replaced_waitpid,                  NULL,                                         ANTIDBG,  0 },
    { "wait3",                  (void*)&replaced_wait3,                    NULL,                                         ANTIDBG,  0 },
    { "waitid",                 (void*)&replaced_waitid,                   NULL,                                         ANTIDBG,  0 },
    { "getrlimit",              (void*)&replaced_getrlimit,                (void**)&original_getrlimit,                ANTIDBG,  ANTIDBG },
    { "proc_listpids",          (void*)&replaced_proc_listpids,            (void**)&original_proc_listpids,            ANTIDBG,  0 },
    { "proc_listallpids",       (void*)&replaced_proc_listallpids,         (void**)&original_proc_listallpids,         ANTIDBG,  0 },
    { "proc_pidinfo",           (void*)&replaced_proc_pidinfo,             (void**)&original_proc_pidinfo,             ANTIDBG,  0 },
    { "proc_pidpath",           (void*)&replaced_proc_pidpath,             (void**)&original_proc_pidpath,             ANTIDBG,  0 },
    { "proc_pidpath_audittoken",(void*)&replaced_proc_pidpath_audittoken,  (void**)&original_proc_pidpath_audittoken,  ANTIDBG,  0 },
    // Phase 4: kill(pid, 0) liveness probe — ESRCH agrees with filtered lists.
    { "kill",                   (void*)&replaced_kill,                     (void**)&original_kill,                     ANTIDBG,  ANTIDBG },
    // Phase 4 pass-throughs (dlsym-policy agreement only — bodies forward
    // untouched; see libc_antidebugging.x rationale per symbol).
    { "uname",                  (void*)&replaced_uname,                   (void**)&original_uname,                   ANTIDBG,  0 },
    { "getifaddrs",             (void*)&replaced_getifaddrs,              (void**)&original_getifaddrs,              ANTIDBG,  0 },
    { "ioctl",                  (void*)&replaced_ioctl,                   (void**)&original_ioctl,                   ANTIDBG,  0 },
};

#undef LIBC
#undef ENVVAR
#undef LOW
#undef ANTIDBG
#undef METADATA

// Fills a NULL-original row's continuation cell from the pre-hook dlsym at
// install (wait family). Defined below, next to the dlsym policy.
static void shdw_libc_resolve_null_original(const char* symbol, void* target);

void shdw_libc_install_group(SHDWHookSession* hooks, uint32_t group) {
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

        // Runtime-resolve; absent optional symbols skip cleanly, absent
        // required ones surface in the group's verify pass. NULL-original
        // rows (wait family) resolve the same way — the target doubles as
        // their continuation (see shdw_libc_resolve_null_original).
        void* target = dlsym(RTLD_DEFAULT, d->symbol);

        if(!target) {
            continue;
        }

        if(!d->original) {
            // NULL-original rows (wait family): the pre-hook target is the
            // continuation. Captured BEFORE the dladdr alias check below
            // (which `continue`s past aliases without installing): an alias
            // that never installs must not leave a stale cell behind, and
            // resolving here keeps the cell in lockstep with the install.
            // The alias check still gates the hookFunction call per row —
            // wait4/waitpid/wait3/waitid are real exports, never aliases.
            shdw_libc_resolve_null_original(d->symbol, target);
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

        // The narrow metadata feature avoids the full filesystem installer
        // on iOS 15 and uses only the path-query hooks it exercises.
        // and keeps every public libc prologue untouched; its Foundation
        // symlink path is covered by the narrow NSFileManager group.
        if(group == SHADW_HOOK_GROUP_FEATURE_METADATA) {
            [hooks hookRebindSymbol:[NSString stringWithUTF8String:d->symbol]
                    withReplacement:d->replacement
                           outOldPtr:d->original];
        // fopen's shared-cache entrypoint is not relocatable on iOS 15;
        // rebind its imports instead of leaving the detector surface open.
        } else if(strcmp(d->symbol, "fopen") == 0) {
            [hooks hookRebindSymbol:@"fopen" withReplacement:d->replacement outOldPtr:d->original];
        // getppid's shared-cache text cannot receive an inline patch on iOS 15.
        // Keep its untouched export as the continuation before HookKit can
        // publish a rebind or journal a late-image replay.
        } else if(group == SHADW_HOOK_GROUP_ANTIDEBUG &&
                  strcmp(d->symbol, "getppid") == 0) {
            if(d->original) {
                *d->original = target;
            }
            [hooks hookRebindSymbol:@"getppid" withReplacement:d->replacement outOldPtr:NULL];
        } else {
            BOOL installed = [hooks hookFunction:target withReplacement:d->replacement outOldPtr:d->original];
            // iOS 15's shared-cache directory entrypoints can be too short or
            // unaligned for a safe entry patch. Rebind their existing imports
            // instead; this leaves the target text untouched and still covers
            // detector call sites already loaded in the process.
            if(!installed && group == SHADW_HOOK_GROUP_LOWLEVEL &&
               (strcmp(d->symbol, "opendir") == 0 || strcmp(d->symbol, "__opendir2") == 0)) {
                installed = [hooks hookRebindSymbol:[NSString stringWithUTF8String:d->symbol]
                                     withReplacement:d->replacement
                                            outOldPtr:d->original];

                if(!installed && strcmp(d->symbol, "__opendir2") == 0) {
                    // No existing import is present in some callers, while
                    // HookKit safely refuses this shared-cache entrypoint's
                    // unaligned text patch. Keep its verified address as the
                    // continuation so dlsym callers still enter the filter.
                    *d->original = target;
                    installed = YES;
                }
            }

            // sysctl's shared-cache export (iOS 15) can refuse a safe inline
            // prologue patch, OR a Swift/ObjC detector may reach sysctl through
            // an import slot the inline patch does not cover. Either way a
            // detector calling sysctl() for KERN_PROC_ALL bypasses the
            // process-list filter (observed: SafetyNet suspicious-process
            // enumeration saw sshd). Additively rebind the sysctl import in
            // caller images so those call sites route through the filter too;
            // the inline hook (when it took) still covers direct-branch
            // callers. Keep the verified export address as the continuation so
            // the replacement can forward when only the rebind took.
            if(group == SHADW_HOOK_GROUP_ANTIDEBUG &&
               strcmp(d->symbol, "sysctl") == 0) {
                [hooks hookRebindSymbol:@"sysctl"
                        withReplacement:d->replacement
                               outOldPtr:d->original];
                if(d->original && *d->original == NULL) {
                    *d->original = target;
                }
                installed = YES;
            }
            (void)installed;
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

void shdw_universal_filesystem_c(SHDWHookSession* hooks) {
    shdw_libc_install_group(hooks, SHADW_HOOK_GROUP_LIBC);
}

void shdw_universal_feature_filesystem_metadata(SHDWHookSession* hooks) {
    shdw_libc_install_group(hooks, SHADW_HOOK_GROUP_FEATURE_METADATA);
}

// Post-install verification: a hook that failed to install (backend error,
// symbol unresolvable) leaves its original_* NULL and the restriction
// silently unenforced. The ctor calls these after executeHooks for the groups
// it installed; each logs any NULL among the group's required symbols.
// Runtime-resolved optional symbols (stat64 family, protected-open variants,
// getmntinfo_r_np, libproc, utimensat) are excluded — NULL there is expected.
void shdw_universal_filesystem_c_verify(void) {
    shdw_libc_verify_group("libc", SHADW_HOOK_GROUP_LIBC);
}

// NULL-original continuations: rows installed with outOldPtr NULL (wait
// family) forward through the pre-hook dlsym captured below at install.
// Same shape as the sandbox resolved_fork fallback: the replacement reads
// the cell per call, and the dlsym policy treats a resolved cell as
// installed.
static void* shdw_wait_continuations[4];

static void shdw_libc_resolve_null_original(const char* symbol, void* target) {
    static const char* const names[] = { "wait4", "waitpid", "wait3", "waitid" };

    for(size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if(strcmp(symbol, names[i]) == 0) {
            shdw_wait_continuations[i] = target;
            return;
        }
    }
}

void* shdw_libc_null_original(const char* symbol) {
    static const char* const names[] = { "wait4", "waitpid", "wait3", "waitid" };

    for(size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if(strcmp(symbol, names[i]) == 0) {
            return shdw_wait_continuations[i];
        }
    }

    return NULL;
}

// Symbol policy for the libc C-function groups (see dyld.x's
// shdw_sym_policy_table): dlsym must resolve every fishhook-rebound libc
// export to its replacement for external callers, so the GOT-vs-dlsym
// comparison agrees. Guarded by the original pointer: a symbol only resolves
// to its replacement when the hook actually installed (original != NULL), so
// runtime-conditional symbols that are absent on a given OS stay absent.
// NULL-original rows (wait family) gate on their resolved continuation cell.
void* shdw_sym_policy_lookup_libc(const char* name) {
    if(!name) {
        return NULL;
    }

    for(size_t i = 0; i < sizeof(shdw_libc_hooks) / sizeof(shdw_libc_hooks[0]); i++) {
        const shdw_hook_desc_t* d = &shdw_libc_hooks[i];

        if(strcmp(name, d->symbol) == 0) {
            if(!d->original) {
                return shdw_libc_null_original(name) ? d->replacement : NULL;
            }

            if(*d->original == NULL) {
                return NULL;  // runtime-conditional symbol not installed
            }

            return d->replacement;
        }
    }

    return NULL;
}

// Reverse of the policy lookup: given a replacement address (what dlsym hands
// an external caller for a hooked libc symbol), return the original function
// address so a dladdr() on it resolves to the genuine system image
// (a function-origin hook check). NULL-original rows resolve through the
// same continuation cells. NULL when the
// address is not a hooked libc replacement.
void* shdw_sym_original_for_replacement_libc(const void* addr) {
    if(!addr) {
        return NULL;
    }
    for(size_t i = 0; i < sizeof(shdw_libc_hooks) / sizeof(shdw_libc_hooks[0]); i++) {
        const shdw_hook_desc_t* d = &shdw_libc_hooks[i];
        if(d->replacement == addr) {
            if(!d->original) {
                return shdw_libc_null_original(d->symbol);
            }
            if(*d->original) {
                return *d->original;
            }
        }
    }
    return NULL;
}
