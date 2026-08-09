#import "Internal/HKBackendInternal.h"

#import <dlfcn.h>
#import <errno.h>

#if __has_include(<ptrauth.h>)
#import <ptrauth.h>
#endif

#import "native/hk_arm64.h"

// Dobby: vendored static lib with arm64/arm64e slices only; the header is
// plain C and safe to include, but the backend class below is arch-gated too
// so armv7 builds never reference DobbyHook/DobbyCodePatch at link time.
#if defined(__arm64__) || defined(__arm64e__)
#include "dobby/dobby.h"
#endif

#pragma mark - HKDobbyBackend

#if defined(__arm64__) || defined(__arm64e__)
@implementation HKDobbyBackend
- (BOOL)batchingSupported {
    return NO;
}

- (BOOL)supportsHookKind:(HKHookKind)kind {
    return kind == HKHookKindFunction || kind == HKHookKindMemory;
}

- (int)lastErrno {
    return _lastErrno;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    _lastErrno = 0;
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)hk_dobby_inline_preflight:(void *)function replacement:(void *)replacement {
    // Fail closed before DobbyHook: Dobby's relocator neither rejects short
    // functions (it reads its 12-16 byte overwrite window without recognizing
    // early exits, smashing whatever follows) nor handles literal loads (it
    // UNIMPLEMENTED()s on some LDR-literal encodings and mishandles SIMD
    // literal loads). The prologue checks below read only the first 16 bytes
    // and never write, so a reject leaves the target untouched.
    if(((uintptr_t)function & 0x3) != 0) {
        _lastErrno = EINVAL;
        return HK_ERR_NOT_SUPPORTED;
    }

    if(function == replacement) {
        _lastErrno = EINVAL;
        return HK_ERR_NOT_SUPPORTED;
    }

    if(hk_arm64_has_early_terminator(function, 16)) {
        // Function ends inside the overwrite window: patching would smash a
        // neighbor's bytes.
        _lastErrno = EOPNOTSUPP;
        return HK_ERR_NOT_SUPPORTED;
    }

    if(hk_arm64_has_aarch64_literal_load(function, 16)) {
        // Literal load / ADR(ADRP) in the overwrite window: the relocator
        // fatally mishandles these.
        _lastErrno = EOPNOTSUPP;
        return HK_ERR_NOT_SUPPORTED;
    }

    return HK_OK;
}

- (hookkit_status_t)preflightFunction:(void *)function withReplacement:(void *)replacement {
    return [self hk_dobby_inline_preflight:function replacement:replacement];
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    _lastErrno = 0;

#if __has_feature(ptrauth_calls)
    // Strip PAC so the raw address is what the relocator will inspect (arm64e).
    function = ptrauth_strip(function, ptrauth_key_asia);
    replacement = ptrauth_strip(replacement, ptrauth_key_asia);
#endif

    hookkit_status_t preflight = [self hk_dobby_inline_preflight:function replacement:replacement];

    if(preflight != HK_OK) {
        // Refused before any write: the target's prologue cannot be
        // overwritten safely (see hk_dobby_inline_preflight).
        return preflight;
    }

    // DobbyHook returns 0 on success; -1 on failure (null address, already
    // hooked, or routing error). Hooks by address — no exported-symbol check.
    // A vendor -1 stays HK_ERR: mutation may already have occurred.
    void *orig = NULL;
    int result = DobbyHook(function, replacement, &orig);
    _lastErrno = result;

    if(result != 0) {
        return HK_ERR;
    }

    if(old_ptr) {
        *old_ptr = orig;
    }

    return HK_OK;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    // DobbyCodePatch returns 0 on success; -1 on failure (invalid arguments
    // or a mach vm_protect error).
    int result = DobbyCodePatch(target, (uint8_t *)data, (uint32_t)size);
    _lastErrno = result;
    return result == 0 ? HK_OK : HK_ERR;
}

- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks {
    // nothing pending: function hooks and memory patches apply at hook time
    return HK_OK;
}
@end
#else   // !arm64: stub — the class symbol must exist for the registry entry,
        // but dobby_available() is NO on armv7 so this is never instantiated.
@implementation HKDobbyBackend
- (BOOL)batchingSupported {
    return NO;
}

- (BOOL)supportsHookKind:(HKHookKind)kind {
    return kind == HKHookKindFunction || kind == HKHookKindMemory;
}

- (int)lastErrno {
    return _lastErrno;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    _lastErrno = 0;
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    _lastErrno = 0;
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    _lastErrno = 0;
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks {
    return HK_OK;
}
// image methods inherited from HKDlfcnBackend: they were NULL stubs here, but
// dobby_available() is NO on armv7 so this class is never instantiated — the
// stub existed only so the class symbol resolves for the registry entry.
@end
#endif

#pragma mark - Frida (HKGum) runtime resolution

// Frida hooks through the HKGum.dylib wrapper, dlopen'd at runtime via
// RootBridge (same pattern as libhooker/libsubstitute): the framework never
// links frida-gum directly. No arch guard — everything is runtime dlopen, and
// on armv7 dlopen simply fails (the wrapper product is arch-gated in the
// Makefile). Theos forces the arm64e slice minos to 14.0, but the arm64 slice
// keeps the deployment floor (9.0/12.0), so HKGum.dylib loads on iOS 12/13 on
// arm64 devices; only on arm64e does dyld refuse below iOS 14. dlopen failure
// is the whole gate (verified: built HKGum arm64 slice carries minos 12.0).
static void *hkgum_handle = NULL;
static int (*fn_hkgum_hook_function)(void *, void *, void **) = NULL;
static int (*fn_hkgum_begin_transaction)(void) = NULL;
static int (*fn_hkgum_end_transaction)(void) = NULL;

// Frida is available when the HKGum.dylib wrapper dlopens (see the resolution
// block above). Only successful probes are cached: if dlopen fails, a later
// call retries.
BOOL frida_available(void) {
    static BOOL cached = NO;
    static BOOL available = NO;

    if(cached) {
        return available;
    }

    NSString *jbPath = HKJBPath(@"/usr/lib/HKGum.dylib");

    if(!jbPath) {
        return NO;
    }

    hkgum_handle = dlopen([jbPath fileSystemRepresentation], RTLD_LAZY);

    if(!hkgum_handle) {
        return NO;
    }

    fn_hkgum_hook_function = (int (*)(void *, void *, void **))dlsym(hkgum_handle, "hkgum_hook_function");
    fn_hkgum_begin_transaction = (int (*)(void))dlsym(hkgum_handle, "hkgum_begin_transaction");
    fn_hkgum_end_transaction = (int (*)(void))dlsym(hkgum_handle, "hkgum_end_transaction");

    available = fn_hkgum_hook_function && fn_hkgum_begin_transaction && fn_hkgum_end_transaction;
    cached = YES;

    return available;
}

#pragma mark - HKFridaBackend

@implementation HKFridaBackend {
    int _lastErrno;
}
- (BOOL)batchingSupported {
    return YES;
}

- (BOOL)supportsHookKind:(HKHookKind)kind {
    return kind == HKHookKindFunction;
}

- (int)lastErrno {
    return _lastErrno;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    _lastErrno = 0;
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    void *orig = NULL;
    int result = fn_hkgum_hook_function(function, replacement, &orig);
    _lastErrno = result;

    if(result != 0) {
        return HK_ERR;
    }

    if(old_ptr) {
        *old_ptr = orig;
    }

    return HK_OK;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    _lastErrno = 0;
    return HK_ERR_NOT_SUPPORTED;
}

// One gum transaction around the whole batch: replacements inside a
// transaction are only published at end_transaction, so the batch is applied
// atomically. Message/memory hooks are not supported (succeeded stays NO).
- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks {
    int total = (int)[hooks count];
    int succeeded = 0;
    int failureErrno = 0;

    fn_hkgum_begin_transaction();

    for(HKHookOperation *hook in hooks) {
        switch(hook->kind) {
            case HKHookKindFunction: {
                void *orig = NULL;
                int result = fn_hkgum_hook_function(hook->function, hook->replacement, &orig);

                if(result == 0) {
                    hook->origValue = orig;
                    hook->succeeded = YES;
                    succeeded += 1;
                } else if(!failureErrno) {
                    failureErrno = result;
                }

                break;
            }

            case HKHookKindMessage:
            case HKHookKindMemory:
                // not supported: succeeded stays NO
                break;
        }
    }

    fn_hkgum_end_transaction();

    _lastErrno = failureErrno;

    return hk_batch_status(succeeded, total);
}
@end