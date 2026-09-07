// Path/fd/dirfd classification. All bodies migrated verbatim from
// hooks/libc.x (and the raw-syscall twin in hooks/syscall.x, which had an
// identical dirfd resolver); a behavior change here changes every hook
// surface at once.

#import "PathPolicy.h"

#import "../hooks/hooks.h"
#import <Shadow/JBPath.h>

#import <string.h>
#import <sys/stat.h>
#import <limits.h>

static _Atomic BOOL shdw_detector_write_policy_active = NO;

void shdw_detector_write_policy_set_enabled(BOOL enabled) {
    atomic_store_explicit(&shdw_detector_write_policy_active, enabled,
                          memory_order_release);
}

BOOL shdw_detector_write_policy_is_enabled(void) {
    return atomic_load_explicit(&shdw_detector_write_policy_active,
                                memory_order_acquire);
}

static BOOL shdw_path_is_within(NSString* path, NSString* root) {
    return path.length && root.length &&
        ([path isEqualToString:root] ||
         [path hasPrefix:[root stringByAppendingString:@"/"]]);
}

BOOL shdw_detector_write_path_denied(NSString* path) {
    if(!shdw_detector_write_policy_is_enabled() || !path.length) {
        return NO;
    }

    Shadow* shadow = [Shadow sharedInstance];
    if(!shadow.hasAppSandbox) return NO;

    @autoreleasepool {
        NSString* absolute = path;
        if(!absolute.isAbsolutePath) {
            char cwd[PATH_MAX];
            if(!getcwd(cwd, sizeof(cwd))) return NO;
            absolute = [[NSString stringWithUTF8String:cwd]
                stringByAppendingPathComponent:absolute];
        }
        absolute = [Shadow getStandardizedPath:absolute];
        if(!absolute.length) return NO;

        NSString* bundleID = [[NSBundle mainBundle] bundleIdentifier];
        if([bundleID hasPrefix:@"me.jjolano.shadow.test."] &&
           shdw_path_is_within(absolute,
               @"/var/mobile/Documents/ShadowDetectorTests")) return NO;
        if(shdw_path_is_within(absolute, shadow.bundlePath)) return YES;
        if(shdw_path_is_within(absolute, shadow.homePath)) return NO;
        if(shdw_path_is_within(absolute,
                @"/var/mobile/Containers/Shared/AppGroup")) return NO;
        if([absolute isEqualToString:@"/dev/null"]) return NO;
        return YES;
    }
}

BOOL shdw_detector_c_write_path_denied(const char* path) {
    return path && shdw_detector_write_path_denied(
        [NSString stringWithUTF8String:path]);
}

// Behavioral tripwire: any non-tweak caller touching a jailbreak-indicator
// path is a detector, whatever it calls itself — renamed, obfuscated, or
// statically linked into the app binary (which has no image name at all for
// the watcher's name scan to see). High-signal set: stock devices never have
// these paths and app code never touches them except to probe.
// ponytail: jb-root prefixes centralized via JBPath shdw_path_contains_restricted_root_c (single source)
BOOL shdw_is_jb_probe(const char* path) {
    if(!path || !path[0]) {
        return NO;
    }

    // Centralized jb-root prefix check (single source: JBPath). Covers
    // /var/jb, /private/preboot, /preboot, /cores and the dynamic jbroot.
    if(shdw_path_contains_restricted_root_c(path)) {
        return YES;
    }

    return strstr(path, "/var/binpack") != NULL
        || strstr(path, "/jbroot") != NULL
        || strstr(path, "/.installed_") != NULL
        || strstr(path, "/.bootstrapped_") != NULL
        || strstr(path, "/var/lib/dpkg") != NULL
        || strstr(path, "/var/lib/apt") != NULL
        || strstr(path, "ShadowCore") != NULL
        || strstr(path, "Shadow.dylib") != NULL
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
    int saved_errno = errno;

    if(path == NULL || path[0] == '\0') {
        // No path semantics to classify here — EFAULT/EINVAL come from the kernel.
        errno = saved_errno;
        return SHADW_DIRFD_ORIGINAL;
    }

    if(path[0] == '/') {
        errno = saved_errno;
        return SHADW_DIRFD_ABSOLUTE;
    }

    if(dirfd == AT_FDCWD) {
        shdw_dirfd_status_t status = getcwd(out, outlen) ? SHADW_DIRFD_OK : SHADW_DIRFD_DENY;
        errno = saved_errno;
        return status;
    }

    if(fcntl(dirfd, F_GETPATH, out) != -1) {
        errno = saved_errno;
        return SHADW_DIRFD_OK;
    }

    struct stat st;

    if(fstat(dirfd, &st) == 0 && S_ISDIR(st.st_mode)) {
        // Valid directory vnode that can't be named: fail closed.
        errno = saved_errno;
        return SHADW_DIRFD_DENY;
    }

    // Invalid or non-directory descriptor: the kernel reports the genuine
    // error (EBADF/ENOTDIR) — never synthesize one here.
    errno = saved_errno;
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

    int saved_errno = errno;
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
        BOOL restricted = [_shadow isPathRestricted:path options:@{
            kShadowRestrictionWorkingDir : [NSString stringWithUTF8String:parent]
        }];

        if(restricted) {
            errno = ENOENT;
            return YES;
        }
    }

    // SHADW_DIRFD_ORIGINAL: let the kernel answer.
    errno = saved_errno;
    return NO;
}

// fd→path classification for the fd-based hooks. F_GETPATH is deliberately
// resolved for every decision: an fd can be replaced by dup2 or renamed by a
// raw syscall without passing a cache-invalidation hook.
BOOL shdw_fd_path_restricted(int fd) {
    int saved_errno = errno;
    char pathname[PATH_MAX];
    BOOL restricted = fcntl(fd, F_GETPATH, pathname) != -1 &&
        [_shadow isCPathRestricted:pathname];
    errno = saved_errno;
    return restricted;
}

// Returns a retained options dict for the DIR*'s parent path (caller must
// CFRelease), or NULL when no filtering applies. Sets *denied when the DIR*
// is a valid directory vnode whose path can't be resolved: entries must be
// hidden (fail closed). *denied is never set for an invalid DIR* — the
// original readdir fails on its own with the genuine EBADF.
NSDictionary* shdw_readdir_options(DIR* dirp, BOOL* denied) {
    int saved_errno = errno;
    *denied = NO;
    char pathname[PATH_MAX];
    shdw_dirfd_status_t status = shdw_resolve_dirfd_path(dirfd(dirp), ".", pathname, sizeof(pathname));

    if(status == SHADW_DIRFD_OK) {
        NSDictionary* options = @{kShadowRestrictionWorkingDir : [NSString stringWithUTF8String:pathname]};
        errno = saved_errno;
        return (__bridge NSDictionary*)CFRetain((__bridge CFDictionaryRef)options);
    }

    if(status == SHADW_DIRFD_DENY) {
        *denied = YES;
        errno = ENOENT;
    } else {
        errno = saved_errno;
    }

    return nil;
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
