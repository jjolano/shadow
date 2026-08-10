#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <stdio.h>
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
#define SHADOW_OWN_IMAGE_MAX 16

typedef struct {
    uintptr_t base, end;
} shdw_range_t;

typedef struct {
    uint32_t count;
    shdw_range_t range[SHADOW_OWN_IMAGE_MAX];
} shdw_own_ranges_t;

extern shdw_own_ranges_t _shdw_own_ranges_a;
extern shdw_own_ranges_t _shdw_own_ranges_b;
extern shdw_own_ranges_t* _shdw_own_ranges_published;   // atomic

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
    return ![Shadow shdwIsInternalRead];
}

// Rebuilds the Shadow-owned image spans from the current dyld image list.
// Called by dyld.x at install and from its add/remove image callbacks.
void shdw_own_ranges_refresh(void);

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
extern void shadowhook_LSApplicationWorkspace(HKSubstitutor* hooks);
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
