// Plugin: Policy_Path — registered in SHDWPluginRegistry (HookConfiguration.m)
#define SHDWPolicyPathPluginID "Policy_Path"

// Path/fd/dirfd classification shared by the libc and raw-syscall hook
// surfaces (hooks/libc.x, hooks/syscall.x): dirfd-aware *at classification,
// fresh fd/DIR path resolution, readlink target resolution and
// the detector-probe classifiers. No caller classification here — the
// isCallerExternal() gates stay at the hook sites. Non-denial classification
// preserves caller errno; denial helpers set their documented policy errno.

#import <Foundation/Foundation.h>
#import <dirent.h>
#import <stddef.h>
#import <sys/types.h>

typedef enum {
    SHADW_DIRFD_OK = 0,        // `out` holds the resolved parent directory
    SHADW_DIRFD_ABSOLUTE,      // path is absolute; dirfd is irrelevant
    SHADW_DIRFD_ORIGINAL,      // replay the original call (kernel reports the genuine error)
    SHADW_DIRFD_DENY,          // valid dir vnode, path unresolvable: fail closed
} shdw_dirfd_status_t;

// Classifies a dirfd+path pair without trusting the fd NUMBER: descriptors
// 0-2 can be closed and reused, so a hook that exempts them filters by
// identity, not number. Absolute paths ignore dirfd entirely; relative
// paths resolve against AT_FDCWD (process cwd) or the dirfd's own path via
// F_GETPATH.
shdw_dirfd_status_t shdw_resolve_dirfd_path(int dirfd, const char* path, char* out, size_t outlen);

// Applies the shared dirfd resolution to one *at path argument: returns YES
// when the query must be denied (errno = ENOENT already set).
BOOL shdw_at_path_denied(int dirfd, const char* pathname);

// fd→path classification for the fd-based hooks (fstat/fstatfs/fpathconf/
// fgetxattr/...): resolves F_GETPATH for every decision, so dup/rename/raw
// syscall mutations cannot retain a stale name. Returns YES when the fd's
// path is restricted; an fd with no nameable path (tty/pipe/socket) is never
// restricted. Leaves errno unchanged when it returns.
BOOL shdw_fd_path_restricted(int fd);

// readdir/readdir_r support: resolves the DIR*'s parent path (dirfd +
// F_GETPATH) for every call and builds a RETAINED options dictionary (caller
// must CFRelease). Sets *denied when the DIR* is a valid directory vnode
// whose path can't be resolved — entries must be hidden (fail closed).
NSDictionary* shdw_readdir_options(DIR* dirp, BOOL* denied);

// Classifies a readlink result: absolute targets are checked directly;
// relative targets resolve against the directory CONTAINING the link (that's
// where the kernel resolves them from). A target whose parent directory
// can't be resolved is denied — never exposed unclassified.
BOOL shdw_readlink_target_restricted(int dirfd, const char* pathname, const char* target);

// Objects that must present a CONSISTENT absent answer to every external API
// (stat/lstat/access/readdir/enumeration), yet stay resolvable to Shadow's own
// loader. These are bind-mounted OVER real system locations or written into
// system dirs, so they can't go through the ruleset path gate (the loader's own
// dlopen/spawn must still see them). One predicate, consulted by every hook
// surface, so no single API can expose what another hides. Exact leaf paths
// plus the structural jb-app-container match.
BOOL shdw_path_is_external_hidden(const char* pathname);

// Directory-listing companion to shdw_path_is_external_hidden: an enumeration
// hook resolves a parent path via F_GETPATH, which can name a bind mount's
// BACKING store instead of its mount point. Returns YES when `d_name` is a
// hidden leaf and `parent` (nullable) is a system bind directory (its mount
// point OR the backing store a jailbreak binds from), so a parent listing
// cannot expose what the point-lookup hooks hide regardless of which name the
// kernel reports for the directory.
BOOL shdw_dir_leaf_external_hidden(const char* parent, const char* d_name);

// YES when `pathname` is at or under a stock system prefix a jailbreak binds
// over (/usr/lib, /usr/libexec, /System). Used to normalise the metadata a
// bind mount over such a path leaks (statfs fs-type, stat device id) back to
// the covering rootfs record.
BOOL shdw_path_under_system_bind_root(const char* pathname);

// YES when `path` is the backing image of injected/hidden code that every
// filesystem, dyld-enumeration and vm_region surface already conceals from
// external callers, so a kernel region->vnode path view cannot reveal it. The
// process's own executable and bundled frameworks are excluded (on rootless
// they live under a jailbreak-root prefix yet are not injected). Routes the
// decision through the SAME image predicate the dyld-enumeration and NSBundle
// hooks use (external-hidden set OR isProtectedImagePath). Callers gate on
// isCallerExternal() at the hook site.
BOOL shdw_region_backing_path_hidden(const char* path);

// libproc/__proc_info region-path callnum + flavors (bsd/sys/proc_info.h; not
// shipped in the theos SDK). PIDINFO is the __proc_info multiplexer sub-call
// libproc's proc_pidinfo issues; the PATHINFO flavors embed the region's
// backing vnode path.
#define SHADOW_PROC_INFO_CALL_PIDINFO   0x2
#define SHADOW_PROC_PIDVNODEPATHINFO      9
#define SHADOW_PROC_PIDREGIONPATHINFO   8
#define SHADOW_PROC_PIDREGIONPATHINFO2  22
#define SHADOW_PROC_PIDREGIONPATHINFO3  23
#define SHADOW_PROC_PIDREGIONPATH       31

// Clears the embedded backing path out of a proc_pidinfo/__proc_info
// region-path result whose image is hidden (shdw_region_backing_path_hidden),
// making that region present as an anonymous (un-named) region — the shape a
// stock anonymous region legitimately has (zero-length name). `flavor` selects
// the result layout; non-path flavors and buffers too small to hold the path
// are left untouched. Same decision the region-path libc hooks use, so the
// libc and raw views agree. Callers gate on isCallerExternal() + own pid at
// the hook site.
void shdw_region_path_result_sanitize(int flavor, void* buffer, int buffersize);

// Rewrites the cwd/root vnode paths of a proc_pidinfo(__proc_info)
// PROC_PIDVNODEPATHINFO(9) result whose path the shared predicates hide
// (external-hidden set, ruleset, protected-image set — the same union the
// region-path view uses), presenting the stock container shape instead: the
// app container for cwd, "/" for root. Paths already inside the own
// bundle/container prefix are untouched. Buffers too small to hold both
// records are left untouched. Callers gate on isCallerExternal() + own pid
// at the hook site.
void shdw_vnodepath_result_sanitize(void* buffer, int buffersize);

// The rootfs (mnton "/") device id, cached from the first stat("/"). Zero if
// unavailable. Used to equalise a system bind mount's st_dev with its parent's.
dev_t shdw_rootfs_dev(void);

// Main-bundle exemption for the open family.
BOOL shdw_path_is_main_bundle_exempt(const char* pathname);

// Behavioral tripwire predicate: any non-tweak caller touching a
// jailbreak-indicator path is a detector, whatever it calls itself —
// renamed, obfuscated, or statically linked into the app binary. High-signal
// set: stock devices never have these paths and app code never touches them
// except to probe. (The trip-on-attempt macro lives in libc.x, which pairs
// this with its own isCallerExternal() expansion.)
BOOL shdw_is_jb_probe(const char* path);

// Once detector behavior is established, reproduce a stock app sandbox's
// write boundary independently of detector names.
void shdw_detector_write_policy_set_enabled(BOOL enabled);
BOOL shdw_detector_write_policy_is_enabled(void);
BOOL shdw_detector_write_path_denied(NSString* path);
BOOL shdw_detector_c_write_path_denied(const char* path);
