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

// Per-return-address cache of isCallerTweak() classifications. A return
// address's classification only changes when the image containing it loads or
// unloads, so a small direct-mapped table keeps the hot path cheap. Each
// entry is two words: the return address + flag (bit 0 = flag, 0 = empty)
// and the dyld image-list generation it was computed at. Writers store
// address+flag first, then the generation (release); readers load the
// generation (acquire) and only trust the entry if it matches the current
// generation — so a classification computed before an image-list change but
// stored after the clear is caught on the next read. The table and
// generation are owned by dyld.x and bumped/cleared on every image add/remove
// callback; when the dyld hooks aren't installed no callbacks run, so the
// cache is skipped entirely (`_shdw_dyld_hooks_active`).
#define SHADOW_CALLER_CACHE_ENTRIES 128

typedef struct {
    uintptr_t gen;      // image-list generation this entry was computed at
    uintptr_t ra_flag;  // return address | flag (bit 0); 0 = empty
} shdw_caller_cache_entry_t;

extern shdw_caller_cache_entry_t _shdw_caller_cache[SHADOW_CALLER_CACHE_ENTRIES];
extern uintptr_t _shdw_caller_cache_generation;
extern BOOL _shdw_dyld_hooks_active;

static inline BOOL shdw_caller_is_tweak(const void* ra) {
    // Without the dyld add/remove callbacks the cache is never invalidated
    // and could serve a stale classification after an unload/reload — always
    // compute instead.
    if(!_shdw_dyld_hooks_active) {
        return [_shadow isAddrExternal:ra];
    }

    uintptr_t key = (uintptr_t) ra;
    uintptr_t generation = __atomic_load_n(&_shdw_caller_cache_generation, __ATOMIC_ACQUIRE);
    shdw_caller_cache_entry_t* slot = &_shdw_caller_cache[(key >> 2) & (SHADOW_CALLER_CACHE_ENTRIES - 1)];

    if(__atomic_load_n(&slot->gen, __ATOMIC_ACQUIRE) == generation) {
        uintptr_t ra_flag = __atomic_load_n(&slot->ra_flag, __ATOMIC_ACQUIRE);

        if((ra_flag & ~(uintptr_t) 1) == key) {
            return (BOOL) (ra_flag & 1);
        }
    }

    BOOL external = [_shadow isAddrExternal:ra];
    __atomic_store_n(&slot->ra_flag, key | (external ? (uintptr_t) 1 : 0), __ATOMIC_RELEASE);
    __atomic_store_n(&slot->gen, generation, __ATOMIC_RELEASE);
    return external;
}

void shdw_caller_cache_invalidate(void);

#define isCallerTweak()         shdw_caller_is_tweak(__builtin_extract_return_addr(__builtin_return_address(0)))

// Set by dylib.x when a known detection library (IOSSecuritySuite/freeRASP)
// is loaded; read by dyld.x to escalate memory-level hiding.
extern BOOL shdw_detector_present;

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
extern void shadowhook_vnode_restore(void);
