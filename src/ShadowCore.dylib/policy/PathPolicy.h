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
