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
#import <stdatomic.h>

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
        || strstr(path, "/binpack") != NULL
        || strstr(path, "/jbroot") != NULL
        || strstr(path, "/.installed_") != NULL
        || strstr(path, "/.bootstrapped_") != NULL
        || strstr(path, "/.procursus_strapped") != NULL
        || strstr(path, "/bootstrap") != NULL
        || strstr(path, "/chimera") != NULL
        || strstr(path, "/odyssey") != NULL
        || strstr(path, "/taurine") != NULL
        || strstr(path, "/meridian") != NULL
        || strstr(path, "/Library/Substitute") != NULL
        || strstr(path, "/etc/apt") != NULL
        || strstr(path, "/var/lib/undecimus") != NULL
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

static BOOL shdw_path_is_jb_app_container(const char* pathname) {
    if(!pathname) return NO;
    const char* rest = NULL;
    if(strncmp(pathname, "/var/mobile/Library/", 20) == 0) rest = pathname + 20;
    else if(strncmp(pathname, "/var/root/Library/", 18) == 0) rest = pathname + 18;
    if(!rest) return NO;

    const char* leaf = strrchr(rest, '/');
    leaf = leaf ? leaf + 1 : rest;

    static const char* const jbAppIDs[] = {
        "com.xina.jailbreak", "com.opa334.Dopamine", "com.tigisoftware.Filza",
        "org.coolstar.SileoStore", "ws.hbang.Terminal", "xyz.willy.Zebra",
        NULL,
    };
    for(int i = 0; jbAppIDs[i]; i++) {
        size_t n = strlen(jbAppIDs[i]);
        if(strncmp(leaf, jbAppIDs[i], n) == 0) return YES;
    }
    return NO;
}

BOOL shdw_path_is_external_hidden(const char* pathname) {
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

BOOL shdw_dir_leaf_external_hidden(const char* parent, const char* d_name) {
    if(!d_name) return NO;
    static const char* const leaves[] = {
        "systemhook.dylib",
        "sandbox.plist",
        NULL,
    };
    BOOL leafHidden = NO;
    for(int i = 0; leaves[i]; i++) {
        if(strcmp(d_name, leaves[i]) == 0) { leafHidden = YES; break; }
    }
    if(!leafHidden) return NO;
    if(!parent || !parent[0]) return NO;
    // The listed directory is a system location a jailbreak binds over, named
    // either by its mount point (/usr/lib, …) or by the backing store the mount
    // comes from (…/.fakelib or …/procursus/basebin). Either way the leaf is
    // the injection artifact the point-lookup hooks already hide.
    if(shdw_path_under_system_bind_root(parent)) return YES;
    if(strstr(parent, ".fakelib") != NULL) return YES;
    if(strstr(parent, "/procursus/basebin") != NULL) return YES;
    return NO;
}

BOOL shdw_path_under_system_bind_root(const char* pathname) {
    if(!pathname) return NO;
    static const char* const roots[] = { "/usr/lib", "/usr/libexec", "/System", NULL };
    for(int i = 0; roots[i]; i++) {
        size_t n = strlen(roots[i]);
        if(strncmp(pathname, roots[i], n) == 0 && (pathname[n] == '\0' || pathname[n] == '/')) {
            return YES;
        }
    }
    return NO;
}

BOOL shdw_path_is_main_bundle_exempt(const char* pathname) {
    if(!pathname || pathname[0] != '/') return NO;
    static NSString* cachedBundle = nil;
    static NSString* cachedExe = nil;
    static dispatch_once_t once = 0;
    dispatch_once(&once, ^{
        CFURLRef burl = CFBundleCopyBundleURL(CFBundleGetMainBundle());
        if(burl) {
            NSURL* nsurl = CFBridgingRelease(burl);
            cachedBundle = [[nsurl path] copy];
        }
        CFURLRef eurl = CFBundleCopyExecutableURL(CFBundleGetMainBundle());
        if(eurl) {
            NSURL* nsurl = CFBridgingRelease(eurl);
            cachedExe = [[nsurl path] copy];
        }
        if(!cachedBundle) cachedBundle = [[[NSBundle mainBundle] bundlePath] copy];
        if(!cachedExe) cachedExe = [[[NSBundle mainBundle] executablePath] copy];
    });
    if(!cachedBundle && !cachedExe) return NO;
    @autoreleasepool {
        NSString* p = [NSString stringWithUTF8String:pathname];
        if(!p) return NO;
        if(cachedExe && [p isEqualToString:cachedExe]) return YES;
        if(cachedBundle && ([p isEqualToString:cachedBundle] ||
           [p hasPrefix:[cachedBundle stringByAppendingString:@"/"]])) return YES;
        return NO;
    }
}

BOOL shdw_region_backing_path_hidden(const char* path) {
    if(!path || !path[0]) return NO;
    @autoreleasepool {
        NSString* p = [NSString stringWithUTF8String:path];
        if(!p) return NO;
        // The process's own executable and bundled frameworks are backed by
        // paths under the app bundle; on a rootless device that prefix lives
        // under a jailbreak-root marker yet is not injected code.
        NSString* bundlePath = [[NSBundle mainBundle] bundlePath];
        if(bundlePath && ([p isEqualToString:bundlePath]
           || [p hasPrefix:[bundlePath stringByAppendingString:@"/"]])) {
            return NO;
        }
        // Same image classification the dyld-enumeration/NSBundle hooks apply:
        // the external-hidden set (systemhook and the bind-covered artifacts)
        // OR the ruleset/protected-image predicate (the jb-root payload +
        // Shadow's own runtime images). One predicate so a region-path view
        // cannot expose what those surfaces hide.
        return shdw_path_is_external_hidden(path) || [_shadow isProtectedImagePath:p];
    }
}

// Region-path result layouts (bsd/sys/proc_info.h; not shipped in the theos
// SDK). Only the flavors that EMBED a path are handled — the fixed-size
// PROC_PIDREGIONINFO (address/size only) carries no name to clear. Layouts are
// the documented public ABI; the path field's offset is all that is read/written.
struct shdw_vinfo_stat {
    uint32_t vst_dev; uint16_t vst_mode; uint16_t vst_nlink; uint64_t vst_ino;
    uint32_t vst_uid; uint32_t vst_gid;
    int64_t vst_atime, vst_atimensec, vst_mtime, vst_mtimensec, vst_ctime, vst_ctimensec;
    int64_t vst_birthtime, vst_birthtimensec, vst_size, vst_blocks;
    int32_t vst_blksize; uint32_t vst_flags; uint32_t vst_gen; uint32_t vst_rdev;
    int64_t vst_qspare[2];
};
struct shdw_vnode_info { struct shdw_vinfo_stat vi_stat; int vi_type; int vi_pad; uint32_t vi_fsid[2]; };
struct shdw_vnode_info_path { struct shdw_vnode_info vip_vi; char vip_path[PATH_MAX]; };
struct shdw_proc_regioninfo {
    uint32_t pri_protection, pri_max_protection, pri_inheritance, pri_flags;
    uint64_t pri_offset;
    uint32_t pri_behavior, pri_user_wired_count, pri_user_tag, pri_pages_resident,
             pri_pages_shared_now_private, pri_pages_swapped_out, pri_pages_dirtied,
             pri_ref_count, pri_shadow_depth, pri_share_mode, pri_private_pages_resident,
             pri_shared_pages_resident, pri_obj_id, pri_depth;
    uint64_t pri_address, pri_size;
};
struct shdw_proc_regionwithpathinfo {
    struct shdw_proc_regioninfo prp_prinfo;
    struct shdw_vnode_info_path prp_vip;
};
struct shdw_proc_regionpath {
    uint64_t prpo_addr; uint64_t prpo_regionlength; char prpo_path[PATH_MAX];
};
struct shdw_proc_vnodepathinfo {
    struct shdw_vnode_info_path pvi_cdir;
    struct shdw_vnode_info_path pvi_rdir;
};

void shdw_region_path_result_sanitize(int flavor, void* buffer, int buffersize) {
    if(!buffer || buffersize <= 0) return;

    // Locate the embedded backing-path field for the flavor's layout. An
    // anonymous (un-named) region legitimately has an empty path here, so
    // clearing a hidden image's name reshapes it into that stock anonymous
    // shape rather than an error.
    char* pathField = NULL;
    if(flavor == SHADOW_PROC_PIDREGIONPATHINFO
       || flavor == SHADOW_PROC_PIDREGIONPATHINFO2
       || flavor == SHADOW_PROC_PIDREGIONPATHINFO3) {
        if((size_t) buffersize < sizeof(struct shdw_proc_regionwithpathinfo)) return;
        pathField = ((struct shdw_proc_regionwithpathinfo*) buffer)->prp_vip.vip_path;
    } else if(flavor == SHADOW_PROC_PIDREGIONPATH) {
        if((size_t) buffersize < sizeof(struct shdw_proc_regionpath)) return;
        pathField = ((struct shdw_proc_regionpath*) buffer)->prpo_path;
    } else {
        return;  // non-path flavor (e.g. PROC_PIDREGIONINFO): nothing to clear
    }

    if(shdw_region_backing_path_hidden(pathField)) {
        pathField[0] = '\0';
    }
}

static BOOL shdw_vnodepath_hidden(const char* path) {
    if(!path || !path[0]) return NO;
    @autoreleasepool {
        // Own bundle/container paths are the process's legitimate location;
        // only a path OUTSIDE that prefix is judged, through the same
        // predicate union the region-path view uses.
        NSString* bundlePath = [[NSBundle mainBundle] bundlePath];
        if(bundlePath && ([@(path) isEqualToString:bundlePath]
           || [@(path) hasPrefix:[bundlePath stringByAppendingString:@"/"]])) {
            return NO;
        }
        NSString* homePath = [_shadow homePath] ?: NSHomeDirectory();
        if(homePath.length && ([@(path) isEqualToString:homePath]
           || [@(path) hasPrefix:[homePath stringByAppendingString:@"/"]])) {
            return NO;
        }
        NSString* p = [NSString stringWithUTF8String:path];
        if(!p) return NO;
        return shdw_path_is_external_hidden(path)
            || [_shadow isCPathRestricted:path]
            || [_shadow isProtectedImagePath:p]
            || shdw_path_contains_restricted_root_c(path);
    }
}

void shdw_vnodepath_result_sanitize(void* buffer, int buffersize) {
    if(!buffer || (size_t) buffersize < sizeof(struct shdw_proc_vnodepathinfo)) return;

    struct shdw_proc_vnodepathinfo* info = (struct shdw_proc_vnodepathinfo*) buffer;
    char* fields[2] = { info->pvi_cdir.vip_path, info->pvi_rdir.vip_path };

    for(int i = 0; i < 2; i++) {
        char* vip_path = fields[i];
        vip_path[PATH_MAX - 1] = '\0';
        if(!shdw_vnodepath_hidden(vip_path)) continue;

        // Stock container shape: the app container for cwd, "/" for root.
        // A replacement that is itself hidden (or missing) falls back to "/",
        // which is never a hidden path. The whole field is cleared first:
        // strlcpy alone leaves the longer original's tail behind, and the
        // kernel buffer is read as raw NUL-terminated strings.
        const char* replacement = "/";
        if(i == 0) {
            NSString* homePath = [_shadow homePath] ?: NSHomeDirectory();
            const char* home = homePath.fileSystemRepresentation;
            if(home && home[0] == '/' && !shdw_vnodepath_hidden(home)
               && strlen(home) < (size_t) PATH_MAX) {
                replacement = home;
            }
        }
        memset(vip_path, 0, PATH_MAX);
        strlcpy(vip_path, replacement, PATH_MAX);
    }
}

dev_t shdw_rootfs_dev(void) {
    static _Atomic(dev_t) cached = 0;
    dev_t d = atomic_load_explicit(&cached, memory_order_acquire);
    if(d != 0) return d;
    int saved_errno = errno;
    struct stat st;
    SHADOW_INTERNAL_SCOPE {
        if(stat("/", &st) == 0) {
            d = st.st_dev;
            atomic_store_explicit(&cached, d, memory_order_release);
        }
    }
    errno = saved_errno;
    return d;
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
        // Absolute operand: dirfd ignored. Same external-hidden set the
        // absolute stat/access hooks apply, then the ruleset.
        if(shdw_path_is_external_hidden(pathname) || [_shadow isCPathRestricted:pathname]) {
            errno = ENOENT;
            return YES;
        }
    } else if(status == SHADW_DIRFD_DENY) {
        errno = ENOENT;
        return YES;
    } else if(status == SHADW_DIRFD_OK) {
        // dirfd + relative leaf: join to the resolved parent and consult the
        // same external-hidden predicates the absolute and readdir hooks use,
        // so a lookup through a directory fd cannot expose what every absolute
        // probe hides. Then the ruleset.
        char joined[PATH_MAX * 2];
        int n = snprintf(joined, sizeof(joined), "%s/%s", parent, pathname);
        if((n > 0 && n < (int)sizeof(joined) && shdw_path_is_external_hidden(joined))
           || shdw_dir_leaf_external_hidden(parent, pathname)) {
            errno = ENOENT;
            return YES;
        }

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
