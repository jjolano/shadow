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

#import <substrate.h>
#import <HookKit.h>

// HookKit overrides
#ifdef hookkit_h
#define MSHookFunction(a,b,c)   [hooks hookFunction:a withReplacement:b outOldPtr:c]
#define MSHookMessageEx         HKHookMessage
#define MSGetImageByName        HKOpenImage
#define MSFindSymbol            HKFindSymbol
#define MSCloseImage            HKCloseImage
#endif

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

// Caller classification for isCallerTweak(): a return address belongs to the
// app iff it falls inside the address range of an image whose path is under
// the app bundle — the predicate -[Shadow isAddrExternal:] applied per call.
// The app bundle's images (app executable + embedded frameworks) are few and
// each span is fixed once its image is loaded, so dyld.x keeps a snapshot of
// their spans instead of answering every call with a dyld image-list walk
// (the old per-return-address table thrashed: ~260 distinct call sites vs
// 128 direct-mapped slots, and every add/remove image forced a wave of
// recomputes). Snapshot is double-buffered: the writer rebuilds the inactive
// copy and publishes it with one release store; readers take one acquire
// load and never see a torn buffer. No callbacks run until dyld.x installs
// them, so before then the published set is empty and every caller
// classifies as non-app (conservative: restrictions apply).
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

static inline BOOL shdw_caller_is_tweak(const void* ra) {
    uintptr_t a = (uintptr_t) ra;
    shdw_own_ranges_t* ranges = __atomic_load_n(&_shdw_own_ranges_published, __ATOMIC_ACQUIRE);

    for(uint32_t i = 0; i < ranges->count; i++) {
        if(a >= ranges->range[i].base && a < ranges->range[i].end) {
            return YES;
        }
    }

    return NO;
}

// Rebuilds the app-bundle image spans from the current dyld image list.
// Called by dyld.x at install and from its add/remove image callbacks.
void shdw_own_ranges_refresh(void);

#define isCallerTweak()         shdw_caller_is_tweak(__builtin_extract_return_addr(__builtin_return_address(0)))

// Set by dylib.x when a known detection library (IOSSecuritySuite/freeRASP)
// is loaded; read by dyld.x to escalate memory-level hiding.
extern BOOL shdw_detector_present;

// Behavioral tripwire escalation (dylib.x): called when a non-tweak caller
// probes the jailbreak (JB-indicator path/symbol/dylib) or a known detector
// loads post-spawn. Idempotent; installs the detector-gated hook groups the
// ctor skipped. Safe to call from hooked functions and the image watcher.
extern void shdw_detector_detected(const char* reason);

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
extern void shadowhook_sandbox(HKSubstitutor* hooks);
extern void shadowhook_syscall(HKSubstitutor* hooks);
extern void shadowhook_UIApplication(HKSubstitutor* hooks);
extern void shadowhook_UIImage(HKSubstitutor* hooks);
extern void shadowhook_libc_envvar(HKSubstitutor* hooks);
extern void shadowhook_libc_lowlevel(HKSubstitutor* hooks);
extern void shadowhook_libc_antidebugging(HKSubstitutor* hooks);
extern void shadowhook_dyld_extra(HKSubstitutor* hooks);
extern void shadowhook_dyld_symlookup(HKSubstitutor* hooks);
extern void shadowhook_dyld_symaddrlookup(HKSubstitutor* hooks);
extern void shadowhook_NSProcessInfo_fakemac(HKSubstitutor* hooks);
extern void shadowhook_mem(HKSubstitutor* hooks);
extern void shadowhook_objc_hidetweakclasses(HKSubstitutor* hooks);
extern void shadowhook_LSApplicationWorkspace(HKSubstitutor* hooks);
extern void shadowhook_NSThread(HKSubstitutor* hooks);
extern void shadowhook_vnode(HKSubstitutor* hooks);
extern void shadowhook_vnode_release(void);
