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
#import <stdint.h>
#import <sys/types.h>

typedef enum {
  SHADW_DIRFD_OK = 0,   // `out` holds the resolved parent directory
  SHADW_DIRFD_ABSOLUTE, // path is absolute; dirfd is irrelevant
  SHADW_DIRFD_ORIGINAL, // replay the original call (kernel reports the genuine
                        // error)
  SHADW_DIRFD_DENY,     // valid dir vnode, path unresolvable: fail closed
} shdw_dirfd_status_t;

// Cheap lexical standardization for hot C string comparison (no
// allocation, no filesystem, no symlink resolution). Collapses duplicate
// slashes, drops "/./" (and trailing "/."), pops "/../" clamped at root,
// preserves a single trailing slash. Returns the input unchanged when
// already canonical or absurdly long, else thread-local scratch valid
// until the next call on this thread — compare immediately, never retain.
const char *shdw_standardize_lexical(const char *path);
// Classifies a dirfd+path pair without trusting the fd NUMBER: descriptors
// 0-2 can be closed and reused, so a hook that exempts them filters by
// identity, not number. Absolute paths ignore dirfd entirely; relative
// paths resolve against AT_FDCWD (process cwd) or the dirfd's own path via
// F_GETPATH.
shdw_dirfd_status_t shdw_resolve_dirfd_path(int dirfd, const char *path,
                                            char *out, size_t outlen);

// Applies the shared dirfd resolution to one *at path argument: returns YES
// when the query must be denied (errno = ENOENT already set).
BOOL shdw_at_path_denied(int dirfd, const char *pathname);

// Entry-identity twin of shdw_at_path_denied for the *at mutators
// (renameat/renameatx_np): identical dirfd resolution, ruleset shape and
// errno contract, but the external-hidden verdict is the nofollow half, so a
// link operand classifies as the entry the kernel will move, not its target.
BOOL shdw_at_path_denied_nofollow(int dirfd, const char *pathname);

// Entry-identity ruleset verdict for the rename family (see the nofollow
// predicate contract above): the NoFollow query — the spelling as named,
// standardized but never kernel-resolved — so an operand reached through an
// alias classifies as the entry the mutator moves, not its target. A
// spelling that names a restricted object still denies; a link that merely
// points at one does not. Total (NULL-safe); leaves errno unchanged.
BOOL shdw_path_ruleset_denied_nofollow(const char *path);

// fd→path classification for the fd-based hooks (fstat/fstatfs/fpathconf/
// fgetxattr/...): resolves F_GETPATH for every decision, so dup/rename/raw
// syscall mutations cannot retain a stale name. Returns YES when the fd's
// path is restricted; an fd with no nameable path (tty/pipe/socket) is never
// restricted. Leaves errno unchanged when it returns.
BOOL shdw_fd_path_restricted(int fd);

// Own-bundle companion to shdw_fd_path_restricted: resolves the fd via
// F_GETPATH and reports whether it names the caller's own bundle, whose
// path lookups the absolute hooks exempt. Reads no caller state (the
// external gate lives at the hook site); leaves errno unchanged. An fd
// with no nameable path is never exempt.
BOOL shdw_fd_path_bundle_exempt(int fd);

// Lexical-only half of shdw_path_is_external_hidden (no filesystem — safe
// on hot paths): the exact list plus the container predicate. Relative
// spellings never match. Pre-call verdicts whose resolving post
// (substitution/fd-verify) already covers the alias window consult this
// instead of the full predicate.
// Lightweight verifier pin for non-stat lanes (access, fileExists) on the
// resolve-stable fast lane: O_RDONLY pin + resolved-union classification,
// no data fill. -1: pinned-hidden or verifier-ENOENT (ENOENT set); 0:
// pinned-and-benign (caller still runs the original plus the bounded
// post); -2: verifier unavailable (errno preserved).
int shdw_verify_open_hidden(int dirfd, const char *pathname);
BOOL shdw_path_is_external_hidden_lexical(const char *path);

// Union check for a kernel-resolved spelling (mount-point OR backing-store
// naming): F_GETPATH can name either for the same object, so both spellings
// must hide. Used by the verify-after-use helpers.
BOOL shdw_resolved_spelling_hidden(const char *canon);

// Verify-after-use for the alias TOCTOU window: the pre-call verdict names
// the request spelling, but a detector-owned symlink can flip before the
// kernel resolves. These re-sample THROUGH THE KERNEL after success and
// report YES only on a positive hidden identification — fail open
// (unresolvable, equal, benign) so any resolver failure keeps the original
// result. No caller classification here (sites gate on ext); errno is
// preserved throughout. Identity (dev,ino) comparison is NOT used: the
// hidden file reports different identities through the bindfs mount than
// canonically (measured on device).
BOOL shdw_fd_names_hidden(int fd);
BOOL shdw_path_post_hidden(const char *path);
BOOL shdw_at_post_hidden(int dirfd, const char *pathname);
// Tri-state re-verification of a successful lookup: re-opens the request
// spelling and classifies the re-opened object with the same resolving
// shape as the substitution verifier (open, F_GETPATH, fstat), so every
// success leg carries the same work. ADMIT keeps the original answer;
// DENY_HIDDEN names a hidden object; DENY_CONTRADICTION fires when the
// spelling re-opens ENOENT right after succeeding (the flip signature —
// an unlink gap or a flip to a dangling spelling). Any other unresolvable
// shape admits (sockets: ENXIO, transient fd pressure), preserving the
// original answer. Errno-preserving; no caller classification (sites gate
// on ext).
typedef enum {
  SHDW_POST_ADMIT = 0,
  SHDW_POST_DENY_HIDDEN,
  SHDW_POST_DENY_CONTRADICTION,
} shdw_post_verdict_t;
shdw_post_verdict_t shdw_at_post_verify(int dirfd, const char *pathname);

// Identity-matched twin of shdw_at_post_verify for the buf-returning stat
// lanes (stat/stat64/fstatat/fstatat64): same single re-open sample
// (open, F_GETPATH, fstat), but a benign classification admits ONLY when
// the re-opened object IS the answered one — same (st_dev, st_ino) as the
// caller already filled in. A live swap between the answer and this sample
// re-names the entry, so the identities diverge and the lookup denies as
// contradictory instead of handing back the previous occupant's identity.
// Same verdict/errno contract as the twin (ENOENT set by the caller, not
// here). Callers gate on ext; answered_* come from the filled answer
// buffer, so buf must be non-NULL at these sites.
shdw_post_verdict_t shdw_at_post_verify_match(int dirfd, const char *pathname,
                                              uint64_t answered_dev,
                                              uint64_t answered_ino);

// Whether a spelling can resolve through attacker-controlled links (pure
// string logic, no filesystem): gates verify-after-use substitution, which
// only pays off where the kernel could resolve elsewhere than the lexical
// verdict names.
BOOL shdw_path_needs_verify(const char *path);

// readdir/readdir_r support: resolves the DIR*'s parent path (dirfd +
// F_GETPATH) for every call and builds a RETAINED options dictionary (caller
// must CFRelease). Sets *denied when the DIR* is a valid directory vnode
// whose path can't be resolved — entries must be hidden (fail closed).
NSDictionary *shdw_readdir_options(DIR *dirp, BOOL *denied);

// Classifies a readlink result: absolute targets are checked directly;
// relative targets resolve against the directory CONTAINING the link (that's
// where the kernel resolves them from). A target whose parent directory
// can't be resolved is denied — never exposed unclassified.
BOOL shdw_readlink_target_restricted(int dirfd, const char *pathname,
                                     const char *target);

// Objects that must present a CONSISTENT absent answer to every external API
// (stat/lstat/access/readdir/enumeration), yet stay resolvable to Shadow's own
// loader. These are bind-mounted OVER real system locations or written into
// system dirs, so they can't go through the ruleset path gate (the loader's own
// dlopen/spawn must still see them). One predicate, consulted by every hook
// surface, so no single API can expose what another hides. Exact leaf paths
// plus the structural jb-app-container match.
BOOL shdw_path_is_external_hidden(const char *pathname);

// Entry-identity half of shdw_path_is_external_hidden for the mutator family
// (rename/renameat/renamex_np/renameatx_np): the kernel operates on the
// directory entry itself and never follows a final-component symlink, so the
// leaf is classified as named — lexical exact list plus the ".."-parent
// second opinion — never kernel-resolved. A spelling that names the hidden
// object still hides; a link that merely points at one renames like any
// other benign entry, exactly as the kernel treats it.
BOOL shdw_path_is_external_hidden_nofollow(const char *pathname);

// Directory-listing companion to shdw_path_is_external_hidden: an enumeration
// hook resolves a parent path via F_GETPATH, which can name a bind mount's
// BACKING store instead of its mount point. Returns YES when `d_name` is a
// hidden leaf and `parent` (nullable) is a system bind directory (its mount
// point OR the backing store a jailbreak binds from), so a parent listing
// cannot expose what the point-lookup hooks hide regardless of which name the
// kernel reports for the directory.
BOOL shdw_dir_leaf_external_hidden(const char *parent, const char *d_name);

// YES when `pathname` is at or under a stock system prefix a jailbreak binds
// over (/usr/lib, /usr/libexec, /System). Used to normalise the metadata a
// bind mount over such a path leaks (statfs fs-type, stat device id) back to
// the covering rootfs record.
BOOL shdw_path_under_system_bind_root(const char *pathname);

// YES when `path` is the backing image of injected/hidden code that every
// filesystem, dyld-enumeration and vm_region surface already conceals from
// external callers, so a kernel region->vnode path view cannot reveal it. The
// process's own executable and bundled frameworks are excluded (on rootless
// they live under a jailbreak-root prefix yet are not injected). Routes the
// decision through the SAME image predicate the dyld-enumeration and NSBundle
// hooks use (external-hidden set OR isProtectedImagePath). Callers gate on
// isCallerExternal() at the hook site.
BOOL shdw_region_backing_path_hidden(const char *path);

// libproc/__proc_info region-path callnum + flavors (bsd/sys/proc_info.h; not
// shipped in the theos SDK). PIDINFO is the __proc_info multiplexer sub-call
// libproc's proc_pidinfo issues; the PATHINFO flavors embed the region's
// backing vnode path.
#define SHADOW_PROC_INFO_CALL_PIDINFO 0x2
#define SHADOW_PROC_PIDVNODEPATHINFO 9
#define SHADOW_PROC_PIDREGIONPATHINFO 8
#define SHADOW_PROC_PIDREGIONPATHINFO2 22
#define SHADOW_PROC_PIDREGIONPATHINFO3 23
#define SHADOW_PROC_PIDREGIONPATH 31

// Clears the embedded backing path out of a proc_pidinfo/__proc_info
// region-path result whose image is hidden (shdw_region_backing_path_hidden),
// making that region present as an anonymous (un-named) region — the shape a
// stock anonymous region legitimately has (zero-length name). `flavor` selects
// the result layout; non-path flavors and buffers too small to hold the path
// are left untouched. Same decision the region-path libc hooks use, so the
// libc and raw views agree. Callers gate on isCallerExternal() + own pid at
// the hook site.
void shdw_region_path_result_sanitize(int flavor, void *buffer, int buffersize);

// Rewrites the cwd/root vnode paths of a proc_pidinfo(__proc_info)
// PROC_PIDVNODEPATHINFO(9) result whose path the shared predicates hide
// (external-hidden set, ruleset, protected-image set — the same union the
// region-path view uses), presenting the stock container shape instead: the
// app container for cwd, "/" for root. Paths already inside the own
// bundle/container prefix are untouched. Buffers too small to hold both
// records are left untouched. Callers gate on isCallerExternal() + own pid
// at the hook site.
void shdw_vnodepath_result_sanitize(void *buffer, int buffersize);

// The rootfs (mnton "/") device id, cached from the first stat("/"). Zero if
// unavailable. Used to equalise a system bind mount's st_dev with its parent's.
dev_t shdw_rootfs_dev(void);

// Main-bundle exemption for the open family.
BOOL shdw_path_is_main_bundle_exempt(const char *pathname);

// Behavioral tripwire predicate: any non-tweak caller touching a
// jailbreak-indicator path is a detector, whatever it calls itself —
// renamed, obfuscated, or statically linked into the app binary. High-signal
// set: stock devices never have these paths and app code never touches them
// except to probe. (The trip-on-attempt macro lives in libc.x, which pairs
// this with its own isCallerExternal() expansion.)
BOOL shdw_is_jb_probe(const char *path);

// Once detector behavior is established, reproduce a stock app sandbox's
// write boundary independently of detector names.
void shdw_detector_write_policy_set_enabled(BOOL enabled);
BOOL shdw_detector_write_policy_is_enabled(void);
BOOL shdw_detector_write_path_denied(NSString *path);
BOOL shdw_detector_c_write_path_denied(const char *path);

// Dirfd-aware twin of shdw_detector_c_write_path_denied for the *at mutators:
// absolute spellings consult the gate directly; relative ones are resolved
// against dirfd first so the verdict names the directory the kernel will
// write, not the process cwd. Unresolvable dirfds admit (the kernel answers
// EBADF, and no staging is possible through a fd the kernel rejects).
// Total (NULL-safe); leaves errno unchanged.
BOOL shdw_detector_c_write_path_at_denied(int dirfd, const char *path);
