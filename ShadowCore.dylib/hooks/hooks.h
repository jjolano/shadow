#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <stdio.h>
#import <stdatomic.h>
#import <sys/stat.h>
#import <sys/statvfs.h>
#import <sys/mount.h>
#import <sys/syscall.h>
#import <sys/utsname.h>
#import <sys/syslimits.h>
#import <sys/time.h>
#import <errno.h>
#import <fcntl.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <mach-o/nlist.h>
#import <dlfcn.h>
#import <dirent.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
#import <mach/task_info.h>
#import <mach/mach_traps.h>
#import <mach/host_special_ports.h>
#import <mach/task_special_ports.h>
#import <sandbox.h>
#import <bootstrap.h>
#import <spawn.h>
#import <objc/runtime.h>

#import "../../common.h"
#import <Shadow.h>

#import <HookKit.h>

// Theos' Logos preprocessor emits MSHookMessageEx for %hook blocks, and
// there is no Logos generator that targets HookKit directly. Route that
// single substrate-compat name into HookKit's native API; everything else
// uses HKSubstitutor calls directly.
#define MSHookMessageEx HKHookMessage

// private symbols
#import "../../vendor/apple/dyld_priv.h"
#import "../../vendor/apple/codesign.h"
#import "../../vendor/apple/ptrace.h"

// `_shadow` is evaluated on every intercepted call; cache the initialized
// singleton behind a single atomic load instead of a dispatch_once check.
// (dispatch_once is still used on the first call per file.) The pointer is
// cached in a plain-C uintptr_t: this toolchain's clang rejects __atomic
// builtins on ObjC pointer types (and _Atomic-wrapped pointers) under ARC,
// but accepts them on plain integers. void* casts are ARC-exempt, and the
// singleton is immortal (retained by +sharedInstance), so the borrowed
// pointer never dangles.
static inline Shadow* shdw_shadow_instance(void) {
    static uintptr_t instance = 0;

    Shadow* cached = (__bridge Shadow *)(void *) __atomic_load_n(&instance, __ATOMIC_ACQUIRE);

    if(!cached) {
        cached = [Shadow sharedInstance];
        __atomic_store_n(&instance, (uintptr_t)(__bridge void *) cached, __ATOMIC_RELEASE);
    }

    return cached;
}

#define _shadow                 shdw_shadow_instance()

// C0-2 caller classification for isCallerExternal(): YES = this caller must
// be shown FILTERED results (app code, embedded/static detectors, system
// frameworks, Foundation forwarding acting on their behalf); NO = Shadow's
// own code, which sees truth. The old model ("any image outside the app
// bundle is a tweak → truth") let every system frame and embedded detector
// bypass filtering; the new model grants truth ONLY to explicit Shadow
// internals: a return address inside one of Shadow's own images
// (Shadow.dylib, Shadow.framework, libSandy.dylib, HookKit,
// substrate/substitute/ellekit) or a thread inside an internal read scope
// (SHADOW_INTERNAL_SCOPE, which sets the +[Shadow shdwIsInternalRead] flag —
// see Core.h; the flag lives in the framework because a C TLS symbol cannot
// cross the framework's -exported_symbols_list).
// This is the predicate -[Shadow isAddrExternal:] applied per call. The
// Shadow-owned images are few and each span is fixed once its image is
// loaded, so dyld.x keeps a snapshot of their spans instead of answering
// every call with a dyld image-list walk (the old per-return-address table
// thrashed: ~260 distinct call sites vs 128 direct-mapped slots, and every
// add/remove image forced a wave of recomputes). Snapshot is
// double-buffered: the writer rebuilds the inactive copy and publishes it
// with one release store; readers take one acquire load and never see a
// torn buffer. dyld.x refreshes the snapshot at install — before any hook
// group installs — and on every add/remove image callback, so the published
// set is never stale in practice.
// NOTE: the collector in dyld.x gathers ONLY the Shadow-owned spans above —
// Shadow.dylib, Shadow.framework, libSandy.dylib, HookKit, and
// substrate/substitute/ellekit, matched by case-insensitive basename via
// isProtectedImagePath — and rebuilds the snapshot at install and on every
// add/remove image callback, so the published set tracks Shadow's loaded
// images. The internal-read scope flag (SHADOW_INTERNAL_SCOPE) remains the
// operative truth signal for Shadow-owned code whose images are not yet
// loaded or refreshed; outside those spans and scopes everyone classifies as
// external, which is the safe (fail-closed) direction.
// The tables themselves, and the pure lookup over them, live in ranges.h so
// the host harness can test the lookup without this file's iOS-only headers.
#import "ranges.h"

extern shdw_own_ranges_t _shdw_own_ranges_a;
extern shdw_own_ranges_t _shdw_own_ranges_b;
extern shdw_own_ranges_t* _shdw_own_ranges_published;   // atomic

// Restricted image spans for shdw_addr_is_restricted() — the address-keyed
// half of the same idea as the own-ranges snapshot above, built in the same
// walk (see shdw_own_ranges_refresh in dyld.x).
//
// -[Shadow isAddrRestricted:] answers "is the image containing this address
// restricted" by calling dyld_image_path_containing_address() — a linear walk
// of every loaded image — and then running the full string pipeline on the
// result. That is an address-keyed question answered by a path-keyed engine,
// once per call, and the hooks ask it in loops: class_copyMethodList asks it
// twice per method of the class, and UIKit's _classWithImplementationOfSelector
// walks a whole class hierarchy, so one appearance setter costs thousands of
// engine queries (observed on-device: Bitwarden, ~18s of launch CPU against a
// ~20s watchdog budget, killed with 0x8BADF00D).
//
// The set of restricted images is small (Shadow's own artifacts plus whatever
// jailbreak images a ruleset denies) and only changes when an image loads or
// the rulesets reload, so classify once per image per change and answer calls
// from a range table — the same trade shdw_own_ranges already makes.
extern shdw_restricted_ranges_t _shdw_restricted_ranges_a;
extern shdw_restricted_ranges_t _shdw_restricted_ranges_b;
extern shdw_restricted_ranges_t* _shdw_restricted_ranges_published;   // atomic

// C0-2 internal-scope primitives for dylib code that needs truth (jailbreakd
// probes, own reads). SHADOW_INTERNAL_SCOPE itself is defined in Core.h and
// works from either binary; these helpers are the dylib-side equivalents of
// the macro's enter/exit halves for finer-grained control.
static inline void shdw_enter_internal(void) {
    [Shadow shdwEnterInternalRead];
}

static inline void shdw_exit_internal(void) {
    [Shadow shdwExitInternalRead];
}

static inline BOOL shdw_caller_is_external(const void* ra) {
    uintptr_t a = (uintptr_t) ra;
    shdw_own_ranges_t* ranges = __atomic_load_n(&_shdw_own_ranges_published, __ATOMIC_ACQUIRE);

    for(uint32_t i = 0; i < ranges->count; i++) {
        if(a >= ranges->range[i].base && a < ranges->range[i].end) {
            return NO;  // inside a Shadow-owned image: Shadow's own code
        }
    }

    // Outside every Shadow-owned span. The snapshot may lag the loaded set
    // (see note above), so also grant truth to a thread in an internal read
    // scope — that keeps the framework's own ruleset/database reads working
    // even before Shadow's images are loaded or the snapshot is refreshed.
    // Read the framework's thread-local through the exported accessor: this
    // is the last thing ~400 hook entry points do before deciding, so an
    // objc_msgSend here is paid at the app's call rate, not Shadow's.
    return shdwInternalBusy() == 0;
}

// Is the image containing `addr` restricted? Same verdict as
// -[Shadow isAddrRestricted:], answered from the snapshot above instead of a
// dyld image walk plus the string pipeline (see shdw_restricted_ranges_t).
//
// Falls back to the real predicate whenever the snapshot cannot be trusted to
// answer completely — it overflowed, or a ruleset reload has landed since it
// was classified. Both fall-backs are correctness-preserving and rare; the
// next refresh republishes a table that answers directly again.
static inline BOOL shdw_addr_is_restricted(const void* addr) {
    shdw_range_verdict_t verdict = shdw_ranges_lookup(
        __atomic_load_n(&_shdw_restricted_ranges_published, __ATOMIC_ACQUIRE),
        atomic_load_explicit(&shdw_ruleset_generation, memory_order_acquire),
        (uintptr_t) addr);

    if(verdict == SHDW_RANGE_UNKNOWN) {
        return [_shadow isAddrRestricted:addr];
    }

    return verdict == SHDW_RANGE_YES;
}

// Rebuilds the Shadow-owned image spans and the restricted image spans from the
// current dyld image list. Called by dyld.x at install and from its add/remove
// image callbacks.
void shdw_own_ranges_refresh(void);

// Exact-basename artifact matcher for Shadow's own runtime images (ShadowCore,
// Shadow.dylib, libSandy, substrate/substitute/ellekit, and the framework
// executable pairs Shadow.framework/Shadow + HookKit.framework/HookKit).
// Defined in dyld.x; shared with objc.x so the class-hiding path reuses the
// same artifact set instead of duplicating it.
BOOL shdw_is_shadow_runtime_image(const char* path);

#define isCallerExternal()         shdw_caller_is_external(__builtin_extract_return_addr(__builtin_return_address(0)))

#define SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path) \
    do { \
        if(isCallerExternal() && [_shadow isPathRestricted:(path)]) { \
            return nil; \
        } \
    } while(0)

#define SHADOW_RETURN_NIL_IF_URL_RESTRICTED(url) \
    do { \
        if(isCallerExternal() && [_shadow isURLRestricted:(url)]) { \
            return nil; \
        } \
    } while(0)

static inline NSDictionary* shdw_restriction_write_options(void) {
    return @{kShadowRestrictionOperation : kShadowRestrictionOpWrite};
}

// Set by dylib.x when a known detection library (IOSSecuritySuite/freeRASP)
// is loaded; read by dyld.x to escalate memory-level hiding.
extern BOOL shdw_detector_present;

// Emergency kill-switch for the dyld_all_image_infos memory-hiding patch
// (AR2). The patch is unconditional by default (untrusted callers read the
// raw struct via task_info / _dyld_get_all_image_infos), but a misbehaving
// patch on a new iOS must be disableable without a reinstall: set by dylib.x
// from the MemoryLevelHiding pref (default YES). When NO, dyld.x restores
// dyld's original struct fields and never re-patches — the direct-memory-read
// surface is re-exposed (detection exposure returns) but the crash stops.
extern BOOL shdw_memory_hiding_enabled;

// Behavioral tripwire escalation (dylib.x): called when a non-tweak caller
// probes the jailbreak (JB-indicator path/symbol/dylib) or a known detector
// loads post-spawn. Idempotent; installs the detector-gated hook groups the
// ctor skipped. Safe to call from hooked functions and the image watcher.
extern void shdw_detector_detected(const char* reason);

// Post-install verification: a hook that failed to install (backend error,
// symbol unresolvable) leaves its original_* NULL and the restriction
// silently unenforced. The hook files expose shadowhook_*_verify functions
// that check their group's required symbols; the ctor calls them after
// executeHooks for the groups it installed. Runtime-resolved optional
// symbols are excluded from the checks — NULL there is expected.
typedef struct {
    const char* name;
    const void* ptr;
} shdw_hook_check_t;

static inline void shdw_verify_hooks(const char* group, const shdw_hook_check_t* checks, size_t count) {
    for(size_t i = 0; i < count; i++) {
        if(!checks[i].ptr) {
            NSLog(@"[Shadow] %s hook not installed: %s", group, checks[i].name);
        }
    }
}

extern void shadowhook_DeviceCheck(HKSubstitutor* hooks);
extern void shadowhook_dyld(HKSubstitutor* hooks);
extern void shadowhook_libc(HKSubstitutor* hooks);
extern void shadowhook_mach(HKSubstitutor* hooks);
extern void shadowhook_NSArray(HKSubstitutor* hooks);
extern void shadowhook_NSBundle(HKSubstitutor* hooks);
extern void shadowhook_NSData(HKSubstitutor* hooks);
extern void shadowhook_NSDictionary(HKSubstitutor* hooks);
extern void shadowhook_NSFileHandle(HKSubstitutor* hooks);
extern void shadowhook_NSFileManager(HKSubstitutor* hooks);
extern void shadowhook_NSFileVersion(HKSubstitutor* hooks);
extern void shadowhook_NSFileWrapper(HKSubstitutor* hooks);
extern void shadowhook_NSProcessInfo(HKSubstitutor* hooks);
extern void shadowhook_NSString(HKSubstitutor* hooks);
extern void shadowhook_NSURL(HKSubstitutor* hooks);
extern void shadowhook_objc(HKSubstitutor* hooks);
extern void shadowhook_objc_methodimpl(HKSubstitutor* hooks);
extern void shadowhook_sandbox(HKSubstitutor* hooks);
extern void shadowhook_syscall(HKSubstitutor* hooks);
extern void shadowhook_UIApplication(HKSubstitutor* hooks);
extern void shadowhook_UIImage(HKSubstitutor* hooks);
extern void shadowhook_libc_envvar(HKSubstitutor* hooks);
extern void shadowhook_envpolicy(HKSubstitutor* hooks);
extern void shadowhook_libc_lowlevel(HKSubstitutor* hooks);
extern void shadowhook_libc_antidebugging(HKSubstitutor* hooks);
extern void shadowhook_dyld_extra(HKSubstitutor* hooks);
extern void shadowhook_dyld_symlookup(HKSubstitutor* hooks);
extern void shadowhook_dyld_symaddrlookup(HKSubstitutor* hooks);

// KERN_PROCARGS2 self-query payload filter (libc.x): rebuilds the kernel's
// [argc][argv][envp][strings] payload so its argv/envp agree with the
// filtered NSProcessInfo/getenv views. Called by the libc sysctl hook, the
// raw syscall dispatch and the sysctlbyname hooks after a successful self
// query. Defined in libc.x (static elsewhere), extern here for syscall.x.
void shdw_procargs2_filter(void* oldp, size_t* oldlenp);

// --- libc split shared surface ---------------------------------------------
// libc.x owns the single shdw_libc_hooks descriptor table and the
// install/verify machinery; the envvar / lowlevel / antidebugging bodies live
// in their own files (libc_envvar.x, libc_lowlevel.x, libc_antidebugging.x)
// and call back into the shared installer/verifier here.

// Trip on the attempt, before any restricted-path filtering: the probe is the
// caller touching a JB indicator, independent of how the filter answers it.
// isCallerExternal() reads the return address, so it must expand inline at the
// hook site — never route it through a helper function. The probe predicate
// itself lives in policy/PathPolicy.m.
#define SHADOW_TRIP(pathname, kind, ext) \
    if(ext && shdw_is_jb_probe(pathname)) { \
        shdw_detector_detected(kind); \
    }

typedef enum {
    SHADW_HOOK_GROUP_LIBC       = 1 << 0,
    SHADW_HOOK_GROUP_ENVVAR     = 1 << 1,
    SHADW_HOOK_GROUP_LOWLEVEL   = 1 << 2,
    SHADW_HOOK_GROUP_ANTIDEBUG  = 1 << 3,
} shdw_hook_group_t;

void shdw_libc_install_group(HKSubstitutor* hooks, uint32_t group);
void shdw_libc_verify_group(const char* group, uint32_t mask);

// struct stat64 is not visible in this build configuration: the SDK guards it
// behind feature macros and omits it entirely on LP64 platforms where struct
// stat already IS the 64-bit layout. Define the 32-bit layout ourselves
// (mirrors xnu's __DARWIN_STRUCT_STAT64) and alias struct stat on LP64.
#if defined(__LP64__)
#define shdw_stat64_t struct stat
#else
struct shdw_stat64 {
    __int32_t    st_dev;
    __uint16_t   st_mode;
    __uint16_t   st_nlink;
    __uint64_t   st_ino;
    __uint32_t   st_uid;
    __uint32_t   st_gid;
    __int32_t    st_rdev;
    struct timespec st_atimespec;
    struct timespec st_mtimespec;
    struct timespec st_ctimespec;
    struct timespec st_birthtimespec;
    __int64_t    st_size;
    __int64_t    st_blocks;
    __int32_t    st_blksize;
    __uint32_t   st_flags;
    __uint32_t   st_gen;
    __int32_t    st_lspare;
    __int64_t    st_qspare[2];
};
#define shdw_stat64_t struct shdw_stat64
#endif

struct ad_open_auth;  // <sys/open.h> is not in the theos SDK

// The descriptor table in libc.x addresses the group bodies by symbol; the
// bodies themselves live in the group files, so the pairs are extern here.
// envvar group (libc_envvar.x)
extern char* (*original_getenv)(const char* name);
extern char* replaced_getenv(const char* name);
// lowlevel group (libc_lowlevel.x)
extern int (*original_open)(const char *pathname, int oflag, ...);
extern int replaced_open(const char *pathname, int oflag, ...);
extern int (*original_openat)(int dirfd, const char *pathname, int oflag, ...);
extern int replaced_openat(int dirfd, const char *pathname, int oflag, ...);
extern DIR* (*original___opendir2)(const char* pathname, int flags);
extern DIR* replaced___opendir2(const char* pathname, int flags);
extern DIR* (*original_opendir)(const char* pathname);
extern DIR* replaced_opendir(const char* pathname);
extern int (*original_open_dprotected_np)(const char* path, int flags, int class, int dpflags, ...);
extern int replaced_open_dprotected_np(const char* path, int flags, int class, int dpflags, ...);
extern int (*original_openat_dprotected_np)(int dirfd, const char* path, int flags, int class, int dpflags, ...);
extern int replaced_openat_dprotected_np(int dirfd, const char* path, int flags, int class, int dpflags, ...);
extern int (*original_openat_authenticated_np)(int dirfd, const char* path, struct ad_open_auth* auth, int flags, ...);
extern int replaced_openat_authenticated_np(int dirfd, const char* path, struct ad_open_auth* auth, int flags, ...);
extern int (*original_stat64)(const char* pathname, shdw_stat64_t* buf);
extern int replaced_stat64(const char* pathname, shdw_stat64_t* buf);
extern int (*original_lstat64)(const char* pathname, shdw_stat64_t* buf);
extern int replaced_lstat64(const char* pathname, shdw_stat64_t* buf);
extern int (*original_fstat64)(int fd, shdw_stat64_t* buf);
extern int replaced_fstat64(int fd, shdw_stat64_t* buf);
extern int (*original_fstatat64)(int dirfd, const char* pathname, shdw_stat64_t* buf, int flags);
extern int replaced_fstatat64(int dirfd, const char* pathname, shdw_stat64_t* buf, int flags);
// antidebugging group (libc_antidebugging.x)
extern int (*original_ptrace)(int _request, pid_t _pid, caddr_t _addr, int _data);
extern int replaced_ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);
extern int (*original_sysctl)(int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen);
extern int replaced_sysctl(int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen);
extern pid_t (*original_getppid)(void);
extern pid_t replaced_getppid(void);
extern int (*original_getrusage)(int who, struct rusage* usage);
extern int replaced_getrusage(int who, struct rusage* usage);
extern int (*original_getrlimit)(int resource, struct rlimit* rlp);
extern int replaced_getrlimit(int resource, struct rlimit* rlp);
extern int (*original_proc_listpids)(uint32_t type, uint32_t typeinfo, void* buffer, int buffersize);
extern int replaced_proc_listpids(uint32_t type, uint32_t typeinfo, void* buffer, int buffersize);
extern int (*original_proc_listallpids)(void* buffer, int buffersize);
extern int replaced_proc_listallpids(void* buffer, int buffersize);
extern int (*original_proc_pidinfo)(int pid, int flavor, uint64_t arg, void* buffer, int buffersize);
extern int replaced_proc_pidinfo(int pid, int flavor, uint64_t arg, void* buffer, int buffersize);

// Symbol policy lookups for the C-function hook groups (libc/mach/sandbox/
// mem). The dlsym hook in dyld.x consults these after its own table misses,
// so every fishhook-rebound export resolves to its replacement for external
// callers — the GOT-vs-dlsym comparison then agrees. Each returns the
// replacement only when that hook actually installed (original != NULL), so
// runtime-conditional symbols that are absent on a given OS stay absent.
void* shdw_sym_policy_lookup_libc(const char* name);
void* shdw_sym_policy_lookup_mach(const char* name);
void* shdw_sym_policy_lookup_sandbox(const char* name);
void* shdw_sym_policy_lookup_mem(const char* name);
// Invalidates the sandbox hook's cached process cwd (defined in sandbox.x;
// called by the libc chdir/fchdir hooks after a successful directory change,
// so a relative-path sandbox query never resolves against a stale cwd).
extern void shdw_sandbox_invalidate_cwd(void);
extern void shadowhook_NSProcessInfo_fakemac(HKSubstitutor* hooks);
extern void shadowhook_mem(HKSubstitutor* hooks);
extern void shadowhook_objc_hidetweakclasses(HKSubstitutor* hooks);
// Shared across the objc satellites (Runtime/objc.x defines; Runtime/objc_hidetweakclasses.x
// and Runtime/objc_methodimpl.x consume): class/address/image hiding predicates and the
// method_getImplementation original cell (rebind lane, defined in objc_methodimpl.x).
extern BOOL shdw_objc_addr_is_hidden(const void* addr);
extern BOOL shdw_objc_image_path_is_hidden(const char* path);
extern BOOL shdw_objc_class_is_hidden(Class cls);
extern IMP (*original_method_getImplementation)(Method m);
extern void shadowhook_LSApplicationWorkspace(HKSubstitutor* hooks);
extern void shadowhook_NSTask(HKSubstitutor* hooks);
extern void shadowhook_NSThread(HKSubstitutor* hooks);
extern void shadowhook_NSUserDefaults(HKSubstitutor* hooks);
extern void shadowhook_iokit(HKSubstitutor* hooks);
extern void shadowhook_iokit_verify(void);
extern void* shdw_sym_policy_lookup_iokit(const char* name);
extern void shadowhook_vnode(HKSubstitutor* hooks);
extern void shadowhook_vnode_release(void);

// B2c: vnode receives the resolved effective VnodeHiding preference from
// dylib.x (the ctor already holds prefs_load) instead of re-reading the
// plist. Call before shadowhook_vnode(NULL) when a resolved pref is
// available; vnode.x falls back to its own plist read when not called.
extern void shdw_vnode_set_pref_enabled(BOOL enabled);

extern void shadowhook_libc_verify(void);
extern void shadowhook_libc_envvar_verify(void);
extern void shadowhook_libc_lowlevel_verify(void);
extern void shadowhook_libc_antidebugging_verify(void);
extern void shadowhook_syscall_verify(void);
extern void shadowhook_mem_verify(void);
extern void shadowhook_mach_verify(void);
extern void shadowhook_sandbox_verify(void);
extern void shadowhook_dyld_verify(void);
extern void shadowhook_dyld_extra_verify(void);
extern void shadowhook_dyld_symlookup_verify(void);
extern void shadowhook_dyld_symaddrlookup_verify(void);
