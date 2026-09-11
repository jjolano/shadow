// Path/fd/dirfd classification. All bodies migrated verbatim from
// hooks/libc.x (and the raw-syscall twin in hooks/syscall.x, which had an
// identical dirfd resolver); a behavior change here changes every hook
// surface at once.

#import "PathPolicy.h"

#import "../hooks/hooks.h"
#import <Shadow/JBPath.h>

#import <fcntl.h>
#import <string.h>
#import <sys/stat.h>
#import <limits.h>
#import <stdatomic.h>
#import <unistd.h>

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

// Cheap lexical standardization for the hot C predicates below (single
// linear-scan fast path; bounded component walk otherwise — no allocation,
// no filesystem, no symlink resolution). Collapses duplicate slashes,
// drops "/./" (and a trailing "/."), and pops "/../" lexically clamped at
// root. A single trailing slash is preserved so a directory spelling never
// compares equal to a file. Returns the input unchanged when already
// canonical, the input unchanged when absurdly long, and thread-local
// scratch otherwise — compare immediately, never retain. "/../" across a
// symlinked component can diverge from the kernel; the predicates below
// close that with a kernel-resolved second opinion (shdw_path_physical_
// spelling) on the residual ".." spellings.
static _Thread_local char shdw_lex_scratch[PATH_MAX];

const char* shdw_standardize_lexical(const char* path) {
    if(!path || path[0] != '/') return path;
    BOOL clean = YES;
    for(const char* p = path; *p; p++) {
        // "//" anywhere, or "/." only when it opens "/./", "/../" or a
        // trailing "/." — dotfile names ("/.hidden") need no work.
        if(p[0] == '/' && (p[1] == '/' || (p[1] == '.' && (p[2] == '/' || p[2] == '.' || p[2] == '\0')))) { clean = NO; break; }
    }
    if(clean) return path;
    size_t len = strlen(path);
    if(len >= sizeof(shdw_lex_scratch)) return path;
    size_t starts[PATH_MAX / 2 + 1];
    size_t depth = 0;
    size_t w = 0;
    shdw_lex_scratch[w++] = '/';
    size_t i = 1;
    BOOL trailing_slash = NO;
    while(i <= len) {
        size_t j = i;
        while(j < len && path[j] != '/') j++;
        size_t clen = j - i;
        BOOL last = (j >= len);
        if(clen == 0) {
            if(last) trailing_slash = YES;
        } else if(clen == 1 && path[i] == '.') {
            // Interior "/./" skipped; trailing "/." dropped (the kernel
            // answers ENOENT for "absent/.", matching the absent lane).
        } else if(clen == 2 && path[i] == '.' && path[i + 1] == '.') {
            if(depth > 0) w = starts[--depth];
            // else clamp at root: drop
        } else {
            if(depth >= sizeof(starts) / sizeof(starts[0])) return path;
            starts[depth++] = w;
            if(w + clen + 2 > sizeof(shdw_lex_scratch)) return path;
            memcpy(shdw_lex_scratch + w, path + i, clen);
            w += clen;
            shdw_lex_scratch[w++] = '/';
        }
        i = j + 1;
    }
    if(!trailing_slash && w > 1) w--;
    shdw_lex_scratch[w] = '\0';
    return shdw_lex_scratch;
}
// Kernel-resolved second opinion for ".." spellings, defined after the
// predicates that consult it so the pinned standardizer extraction above
// stays self-contained.
static const char* shdw_path_physical_spelling(const char* path);
// Immutable system prefixes for alias resolution below: no sandboxed caller
// can plant a symlink under them, so a spelling rooted here cannot alias
// anywhere else through an attacker-controlled link. Deliberately tight —
// anything not listed resolves (fail closed, costs an open, stays correct).
static BOOL shdw_path_under_immutable_prefix(const char* path);
// Full kernel-spelling resolution (parent AND final-component links) for
// alias coverage, defined after the predicates that consult it so the
// pinned standardizer extraction above stays self-contained.
static const char* shdw_path_kernel_spelling(const char* path);
// Union check for a kernel-resolved spelling (mount-point OR backing-store
// naming), defined after the leaf check it consults so the pinned
// standardizer extraction above stays self-contained.
BOOL shdw_resolved_spelling_hidden(const char* canon);
// Lexical-only half of the hidden predicate (no filesystem): the exact
// list plus the container predicate over the standardized spelling.
// Relative spellings never match (callers join first). Exported for
// pre-call verdicts whose resolving post already covers aliases.
BOOL shdw_path_is_external_hidden_lexical(const char* path) {
    if(!path || path[0] != '/') return NO;
    // Compare the standardized spelling: detectors routinely probe
    // "//", "/./" and "/../" variants of the same object.
    const char* std = shdw_standardize_lexical(path);
    // Classification names the object, and a trailing slash never changes
    // which object that is: match the exact list with one trailing slash
    // ignored so a directory spelling of a hidden file hides like the file.
    size_t n = strlen(std);
    if(n > 1 && std[n - 1] == '/') n--;
    static const char* const paths[] = {
        "/usr/lib/systemhook.dylib",
        "/usr/lib/sandbox.plist",
        "/var/log/launchdhook.log",
        NULL,
    };
    for(int i = 0; paths[i]; i++) {
        if(strlen(paths[i]) == n && strncmp(std, paths[i], n) == 0) return YES;
    }
    return shdw_path_is_jb_app_container(std);
}
BOOL shdw_path_is_external_hidden(const char* pathname) {
    if(!pathname) return NO;
    // Bare relative lookup: the kernel resolves against the physical cwd
    // vnode, so classify the joined spelling, not the bare leaf (which no
    // exact list can carry). open(".")+F_GETPATH names the vnode without
    // getcwd's fallback scan; an unresolvable cwd falls through to the
    // lexical verdict below (always miss for relative spellings — the
    // kernel fails those lookups the same way). Absolute spellings skip
    // this entirely, so dirfd-joined callers pay nothing extra.
    if(pathname[0] != '/') {
        int saved_errno = errno;
        int fd = open(".", O_RDONLY | O_CLOEXEC);
        if(fd >= 0) {
            char cwd[PATH_MAX];
            BOOL ok = fcntl(fd, F_GETPATH, cwd) != -1;
            close(fd);
            errno = saved_errno;
            if(ok) {
                char joined[PATH_MAX * 2];
                int n = snprintf(joined, sizeof(joined), "%s/%s", cwd, pathname);
                if(n > 0 && n < (int)sizeof(joined)) {
                    return shdw_path_is_external_hidden(joined);
                }
            }
        } else {
            errno = saved_errno;
        }
    }
    // The lexical half below (no filesystem) is also consulted directly by
    // pre-call verdicts whose resolving post (substitution/fd-verify)
    // already covers the alias window — paying a second resolving open in
    // pre would double the gate's timing cost for zero added coverage.
    const char* raw = pathname;
    if(shdw_path_is_external_hidden_lexical(pathname)) return YES;
    // A ".." the lexical pass popped on the spelling may pop on a symlink
    // target in the kernel: re-check the spelling the kernel answers for.
    // The physical form is canonical, so this recurses at most once.
    const char* physical = shdw_path_physical_spelling(raw);
    BOOL physicalHit = physical && shdw_path_is_external_hidden(physical);
    if(physicalHit) return YES;
    // A bare alias (no ".." anywhere): the link target is only visible to
    // the kernel, so resolve the full spelling and re-check that. Covers
    // parent-directory aliases and final-component links in one traversal;
    // confined to attacker-reachable prefixes (see the gate), so system
    // hot paths pay one prefix scan. Canonical output recurses at most once.
    const char* kernel = shdw_path_kernel_spelling(raw);
    BOOL kernelHit = kernel && shdw_resolved_spelling_hidden(kernel);
    if(kernelHit) return YES;
    return NO;
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
    // Standardize the parent: user-controlled directory spellings ("//",
    // "/./") must classify like the kernel-resolved form.
    parent = shdw_standardize_lexical(parent);
    // The listed directory is a system location a jailbreak binds over, named
    // either by its mount point (/usr/lib, …) or by the backing store the mount
    // comes from (…/.fakelib or …/procursus/basebin). Either way the leaf is
    // the injection artifact the point-lookup hooks already hide.
    if(shdw_path_under_system_bind_root(parent)) return YES;
    if(strstr(parent, ".fakelib") != NULL) return YES;
    if(strstr(parent, "/procursus/basebin") != NULL) return YES;
    return NO;
}
// Union check for a kernel-resolved spelling: F_GETPATH can name a bind
// mount's BACKING store (.../procursus/basebin/...) instead of its mount
// point (/usr/lib/...) for the same object, depending on how the lookup
// traversed into the mount (measured on device). The enumeration hooks
// already classify that union through the leaf check — apply it to the
// resolved spelling too, so either naming hides.
BOOL shdw_resolved_spelling_hidden(const char* canon) {
    if(!canon || canon[0] == '\0') return NO;
    if(shdw_path_is_external_hidden(canon)) return YES;
    const char* slash = strrchr(canon, '/');
    if(!slash || slash == canon || slash[1] == '\0') return NO;
    char parent[PATH_MAX];
    size_t pn = (size_t)(slash - canon);
    if(pn >= sizeof(parent)) return NO;
    memcpy(parent, canon, pn);
    parent[pn] = '\0';
    return shdw_dir_leaf_external_hidden(parent, slash + 1);
}

BOOL shdw_path_under_system_bind_root(const char* pathname) {
    if(!pathname) return NO;
    // Standardize first: every caller benefits, and kernel-equivalent
    // spellings must classify identically.
    pathname = shdw_standardize_lexical(pathname);
    static const char* const roots[] = { "/usr/lib", "/usr/libexec", "/System", NULL };
    for(int i = 0; roots[i]; i++) {
        size_t n = strlen(roots[i]);
        if(strncmp(pathname, roots[i], n) == 0 && (pathname[n] == '\0' || pathname[n] == '/')) {
            return YES;
        }
    }
    return NO;
}
// Verifier pin for non-stat lanes (access, fileExists): pin the object
// with O_RDONLY|O_NONBLOCK and classify it, without filling data. Returns
// -1 (pinned-hidden or verifier-ENOENT, ENOENT set), 0 (pinned-and-benign
// — caller still runs the original for the authoritative answer plus the
// bounded post), or -2 (verifier unavailable — caller falls back). No
// CREAT/TRUNC flag exists on this path, so the lookup cannot mutate.
// Callers gate on fully-allowed lookups; errno is preserved on the -2 path.
int shdw_verify_open_hidden(int dirfd, const char* pathname) {
    int vfd = openat(dirfd, pathname, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if(vfd < 0) {
        if(errno == ENOENT) {
            return -1;
        }
        return -2;
    }
    char canon[PATH_MAX];
    int r = -2;
    if(fcntl(vfd, F_GETPATH, canon) != -1) {
        r = shdw_resolved_spelling_hidden(canon) ? -1 : 0;
        if(r == -1) errno = ENOENT;
    }
    close(vfd);
    return r;
}

BOOL shdw_path_is_main_bundle_exempt(const char* pathname) {
    if(!pathname || pathname[0] != '/') return NO;
    // The ".." gate below must see the raw spelling (standardization pops
    // ".." lexically, which is exactly what can diverge across a symlink).
    const char* raw = pathname;
    // Compare the standardized spelling so "//" and "/./" variants of an
    // exempt location resolve exactly like the canonical form.
    pathname = shdw_standardize_lexical(pathname);
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
        // A ".." the lexical pass popped on the spelling may pop on a
        // symlink target in the kernel: an exempt location spelled through
        // one still exempts. The physical form is canonical, so this
        // recurses at most once.
        const char* physical = shdw_path_physical_spelling(raw);
        if(physical && shdw_path_is_main_bundle_exempt(physical)) return YES;
        return NO;
    }
}
// Physical second opinion for ".." spellings: the lexical pass above pops
// ".." on the spelling, but the kernel pops it on the target when the left
// sibling names a symlink, so the two can resolve to different objects.
// When the spelling contains ".." and the lexical verdict missed, the
// parent directory is resolved through the kernel (open + F_GETPATH) and
// the leaf re-attached, yielding the spelling the kernel actually answers
// for. Parent-only, never the leaf: resolving the leaf itself would follow
// a trailing symlink and change what the caller asked about. Returns NULL
// when there is no "..", when the parent cannot be opened, or when the
// physical spelling equals the input (the lexical verdict then stands).
// Thread-local scratch, compare immediately, never retain. Only reached on
// a lexical miss, so the steady state pays one substring scan, not one open.
// O_PATH does not exist on Darwin, so the parent directory fd carries the
// resolution instead. Caller errno is preserved throughout.
static _Thread_local char shdw_physical_scratch[PATH_MAX];

static const char* shdw_path_physical_spelling(const char* path) {
    if(!path || path[0] != '/' || strstr(path, "..") == NULL) {
        return NULL;
    }
    size_t len = strlen(path);
    if(len >= sizeof(shdw_physical_scratch)) {
        return NULL;
    }
    // Split off the leaf without resolving it; a trailing slash belongs to
    // the parent (a directory spelling).
    size_t end = len;
    while(end > 1 && path[end - 1] == '/') end--;
    size_t slash = end;
    while(slash > 0 && path[slash - 1] != '/') slash--;
    if(slash == 0 || end - slash < 1) {
        return NULL;
    }
    // A dot or dot-dot leaf is already decided lexically; re-resolving it
    // can only echo the input back.
    if((end - slash == 1 && path[slash] == '.') ||
       (end - slash == 2 && path[slash] == '.' && path[slash + 1] == '.')) {
        return NULL;
    }
    int saved_errno = errno;
    const char* physical = NULL;
    // The parent may itself end in a slash after the split; open(2)
    // tolerates that on directories.
    char parent[PATH_MAX];
    if(slash < sizeof(parent)) {
        memcpy(parent, path, slash);
        parent[slash] = '\0';
        int fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if(fd >= 0) {
            char resolved[PATH_MAX];
            if(fcntl(fd, F_GETPATH, resolved) != -1) {
                size_t rn = strlen(resolved);
                size_t leafn = end - slash;
                if(rn + 1 + leafn < sizeof(shdw_physical_scratch)) {
                    memcpy(shdw_physical_scratch, resolved, rn);
                    shdw_physical_scratch[rn] = '/';
                    memcpy(shdw_physical_scratch + rn + 1, path + slash, leafn);
                    shdw_physical_scratch[rn + 1 + leafn] = '\0';
                    if(strcmp(shdw_physical_scratch, path) != 0) {
                        physical = shdw_physical_scratch;
                    }
                }
            }
            close(fd);
        }
    }
    errno = saved_errno;
    return physical;
}
// Whether a spelling can resolve through attacker-controlled links (see the
// definition after the immutable gate): gates verify-after-use
// substitution, which only pays off where the kernel could resolve
// elsewhere than the lexical verdict names.
BOOL shdw_path_needs_verify(const char* path);
// Immutable system prefixes: no sandboxed caller can plant a symlink under
// them, so a spelling rooted here cannot alias anywhere else through an
// attacker-controlled link. Deliberately tight — anything not listed
// resolves (fail closed, costs an open, stays correct).
static BOOL shdw_path_under_immutable_prefix(const char* path) {
    if(!path || path[0] != '/') return NO;
    static const char* const roots[] = {
        "/usr/", "/System/", "/bin/", "/sbin/", "/etc/", "/private/etc/",
        "/Library/", "/Applications/", "/Developer/", "/cores/", "/dev/",
        "/private/preboot/", "/preboot/", "/var/jb/", "/private/var/jb/",
        NULL,
    };
    for(int i = 0; roots[i]; i++) {
        size_t n = strlen(roots[i]);
        if(strncmp(path, roots[i], n) == 0) return YES;
    }
    return NO;
}

// Whether a spelling can resolve through attacker-controlled links: anything
// but an absolute, dotdot-free path under an immutable prefix. Relative
// spellings follow the (flippable) cwd, ".." can climb out of immutable
// roots, and anything elsewhere may traverse a planted symlink. Pure string
// logic, no filesystem, no errno effect — safe to consult on hot paths.
BOOL shdw_path_needs_verify(const char* path) {
    if(!path || path[0] == '\0') return NO;
    if(path[0] != '/') return YES;
    if(strstr(path, "..") != NULL) return YES;
    return !shdw_path_under_immutable_prefix(path);
}
// Full kernel-spelling resolution for alias coverage: opens the path itself
// (following parent AND final-component links in one kernel traversal) and
// returns F_GETPATH's canonical spelling when it differs. Identity
// comparison cannot do this job (measured: the hidden file reports
// different (st_dev, st_ino) through the bindfs mount than canonically).
// Gated to attacker-reachable areas (above) so system hot paths pay one
// prefix scan, not one open. O_NONBLOCK so a fifo alias cannot hang the
// lookup; dangling or unsearchable paths fail NULL and the lexical verdict
// stands (the kernel fails those lookups the same way). Thread-local
// scratch, compare immediately, never retain. Caller errno is preserved.
static _Thread_local char shdw_kernel_scratch[PATH_MAX];

static const char* shdw_path_kernel_spelling(const char* path) {
    if(!path || path[0] != '/' || shdw_path_under_immutable_prefix(path)) {
        return NULL;
    }
    size_t len = strlen(path);
    if(len <= 1 || len >= sizeof(shdw_kernel_scratch)) {
        return NULL;
    }
    int saved_errno = errno;
    const char* spelling = NULL;
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if(fd >= 0) {
        char canon[PATH_MAX];
        if(fcntl(fd, F_GETPATH, canon) != -1 && strcmp(canon, path) != 0) {
            size_t cn = strlen(canon);
            if(cn < sizeof(shdw_kernel_scratch)) {
                memcpy(shdw_kernel_scratch, canon, cn + 1);
                spelling = shdw_kernel_scratch;
            }
        }
        close(fd);
    }
    errno = saved_errno;
    return spelling;
}

// Verify-after-use for the alias TOCTOU window (see the header contract):
// re-sample through the kernel after the original call succeeded and deny
// only on a positive hidden identification. Lexical re-classification is
// deliberately skipped — the request string cannot change between the
// pre-call verdict and here, only its resolution can.
BOOL shdw_fd_names_hidden(int fd) {
    int saved_errno = errno;
    char canon[PATH_MAX];
    BOOL hidden = fd >= 0 && fcntl(fd, F_GETPATH, canon) != -1 &&
        shdw_resolved_spelling_hidden(canon);
    errno = saved_errno;
    return hidden;
}

BOOL shdw_path_post_hidden(const char* path) {
    if(!path || !path[0]) return NO;
    int saved_errno = errno;
    BOOL hidden = NO;
    if(path[0] != '/') {
        int fd = open(".", O_RDONLY | O_CLOEXEC);
        if(fd >= 0) {
            char cwd[PATH_MAX];
            if(fcntl(fd, F_GETPATH, cwd) != -1) {
                char joined[PATH_MAX * 2];
                int n = snprintf(joined, sizeof(joined), "%s/%s", cwd, path);
                if(n > 0 && n < (int)sizeof(joined)) {
                    const char* k = shdw_path_kernel_spelling(joined);
                    hidden = k && shdw_resolved_spelling_hidden(k);
                }
            }
            close(fd);
        }
    } else {
        const char* k = shdw_path_kernel_spelling(path);
        hidden = k && shdw_resolved_spelling_hidden(k);
    }
    errno = saved_errno;
    return hidden;
}

// Tri-state re-verification of a successful lookup (see the header
// contract): re-open the request spelling and classify the re-opened
// object with the same resolving shape as the substitution verifier.
shdw_post_verdict_t shdw_at_post_verify(int dirfd, const char* pathname) {
    if(!pathname || !pathname[0]) return SHDW_POST_ADMIT;
    int saved_errno = errno;
    shdw_post_verdict_t verdict = SHDW_POST_ADMIT;
    int fd = openat(dirfd, pathname, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if(fd < 0) {
        // Vanished within microseconds of a success: the flip signature
        // (unlink gap or flip to a dangling spelling). Any other open
        // failure admits, preserving the original answer's shape.
        verdict = (errno == ENOENT) ? SHDW_POST_DENY_CONTRADICTION : SHDW_POST_ADMIT;
    } else {
        char canon[PATH_MAX];
        struct stat sb;
        // The fstat confirms the re-opened witness is statable before it
        // is classified, exactly as the substitution verifier does.
        if(fcntl(fd, F_GETPATH, canon) != -1 && fstat(fd, &sb) == 0) {
            verdict = shdw_resolved_spelling_hidden(canon) ? SHDW_POST_DENY_HIDDEN : SHDW_POST_ADMIT;
        }
        close(fd);
    }
    errno = saved_errno;
    return verdict;
}
BOOL shdw_at_post_hidden(int dirfd, const char* pathname) {
    if(!pathname || !pathname[0]) return NO;
    if(pathname[0] == '/') return shdw_path_post_hidden(pathname);
    int saved_errno = errno;
    BOOL hidden = NO;
    char parent[PATH_MAX];
    if(shdw_resolve_dirfd_path(dirfd, pathname, parent, sizeof(parent)) == SHADW_DIRFD_OK) {
        char joined[PATH_MAX * 2];
        int n = snprintf(joined, sizeof(joined), "%s/%s", parent, pathname);
        if(n > 0 && n < (int)sizeof(joined)) {
            hidden = shdw_path_post_hidden(joined);
        }
    }
    errno = saved_errno;
    return hidden;
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

BOOL shdw_fd_path_bundle_exempt(int fd) {
    int saved_errno = errno;
    char pathname[PATH_MAX];
    BOOL exempt = fcntl(fd, F_GETPATH, pathname) != -1 &&
        shdw_path_is_main_bundle_exempt(pathname);
    errno = saved_errno;
    return exempt;
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
