// Path/fd/dirfd classification. All bodies migrated verbatim from
// hooks/libc.x (and the raw-syscall twin in hooks/syscall.x, which had an
// identical dirfd resolver); a behavior change here changes every hook
// surface at once.

#import "PathPolicy.h"

#import "../hooks/hooks.h"

#import <string.h>
#import <os/lock.h>
#import <sys/stat.h>
#import <limits.h>

// Behavioral tripwire: any non-tweak caller touching a jailbreak-indicator
// path is a detector, whatever it calls itself — renamed, obfuscated, or
// statically linked into the app binary (which has no image name at all for
// the watcher's name scan to see). High-signal set: stock devices never have
// these paths and app code never touches them except to probe.
BOOL shdw_is_jb_probe(const char* path) {
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
shdw_dirfd_status_t shdw_resolve_dirfd_path(int dirfd, const char* path, char* out, size_t outlen) {
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
BOOL shdw_at_path_denied(int dirfd, const char* pathname) {
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

BOOL shdw_fd_path_restricted(int fd) {
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

void shdw_fd_cache_invalidate(int fd) {
    os_unfair_lock_lock(&shdw_fd_cache_lock);

    for(NSUInteger i = 0; i < SHADW_FD_CACHE_SIZE; i++) {
        if(shdw_fd_cache[i].fd == fd) {
            shdw_fd_cache[i].fd = -1;
            shdw_fd_cache[i].valid = NO;
            break;
        }
    }

    os_unfair_lock_unlock(&shdw_fd_cache_lock);
}

// readdir/readdir_r used to resolve the DIR*'s parent path (dirfd + F_GETPATH)
// and build the options dictionary for every entry. Cache both per DIR* so
// only the per-entry child check runs; invalidated on closedir because DIR*
// pointers get reused. Fixed-size table, round-robin eviction on overflow
// (a miss just re-resolves — results stay identical). A valid directory
// vnode whose path can't be resolved is cached as DENIED: entries are hidden
// (fail closed) rather than exposed unfiltered.
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
NSDictionary* shdw_readdir_cache_options(DIR* dirp, BOOL* denied) {
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

void shdw_readdir_cache_clear(DIR* dirp) {
    os_unfair_lock_lock(&shdw_readdir_cache_lock);
    shdw_readdir_cache_clear_locked(dirp);
    os_unfair_lock_unlock(&shdw_readdir_cache_lock);
}

// Classifies a readlink result: absolute targets are checked directly;
// relative targets resolve against the directory CONTAINING the link (that's
// where the kernel resolves them from). A target whose parent directory can't
// be resolved is denied — never exposed unclassified.
BOOL shdw_readlink_target_restricted(int dirfd, const char* pathname, const char* target) {
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

// freeRASP rootless probe: writing under @executable_path/.jbroot succeeds on
// jailbroken devices (symlink into writable bootstrap) and fails on stock.
// Fail the same way stock does (ENOENT — the path doesn't resolve). The
// probe is matched as an exact path COMPONENT under the app's bundle
// directory: a substring match would trip on benign names like
// "notajbrootfile". Deny only when a path component equals ".jbroot" and the
// components before it are exactly the app bundle dir.
BOOL shdw_is_jbroot_write_probe(const char* pathname, int oflag) {
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