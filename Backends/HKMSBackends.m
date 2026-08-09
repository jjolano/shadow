#import "Internal/HKBackendInternal.h"

#import <dlfcn.h>
#import <errno.h>
#import <objc/runtime.h>

#import "vendor/substrate/substrate.h"
#import "vendor/substitute/substitute.h"
#import "Internal/HKSubstituteErrors.h"

#pragma mark - Cydia Substrate / Substitute (MS-compatible API) runtime resolution

// Both libraries expose the classic Cydia Substrate C API. Cydia Substrate
// exports the MS* symbols directly; libsubstitute exports them under MS*
// (older versions) or Sub* (newer versions) names, so try both.
static void *substrate_handle = NULL;
static void (*substrate_hookFunction)(void *, void *, void **) = NULL;
static void (*substrate_hookMessageEx)(Class, SEL, void *, void **) = NULL;
static void *(*substrate_getImageByName)(const char *) = NULL;
static void *(*substrate_findSymbol)(void *, const char *) = NULL;
static void (*substrate_hookMemory)(void *, const void *, size_t) = NULL;

// Only successful probes are cached: if dlopen fails, a later call retries
// (the engine may appear after HookKit loads).
BOOL substrate_available(void) {
    static BOOL cached = NO;
    static BOOL available = NO;

    if(cached) {
        return available;
    }

    NSString *jbPath = HKJBPath(@"/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate");

    if(!jbPath) {
        return NO;
    }

    void *handle = dlopen([jbPath fileSystemRepresentation], RTLD_LAZY);

    if(!handle) {
        return NO;
    }

    // Resolve into locals first: the globals are published only after the
    // ENTIRE required symbol set is present, so an incomplete library can
    // never leave half-populated function pointers behind.
    void (*hookFunction)(void *, void *, void **) = (void (*)(void *, void *, void **))dlsym(handle, "MSHookFunction");
    void (*hookMessageEx)(Class, SEL, void *, void **) = (void (*)(Class, SEL, void *, void **))dlsym(handle, "MSHookMessageEx");
    void *(*getImageByName)(const char *) = (void *(*)(const char *))dlsym(handle, "MSGetImageByName");
    void *(*findSymbol)(void *, const char *) = (void *(*)(void *, const char *))dlsym(handle, "MSFindSymbol");
    void (*hookMemory)(void *, const void *, size_t) = (void (*)(void *, const void *, size_t))dlsym(handle, "MSHookMemory");

    // ABI-incomplete: drop the handle and stay uncached so a later probe
    // genuinely retries (the engine may gain the full ABI after HookKit
    // loads). Nothing was published.
    if(!(hookFunction && hookMessageEx && getImageByName && findSymbol)) {
        dlclose(handle);
        return NO;
    }

    substrate_handle = handle;
    substrate_hookFunction = hookFunction;
    substrate_hookMessageEx = hookMessageEx;
    substrate_getImageByName = getImageByName;
    substrate_findSymbol = findSymbol;
    substrate_hookMemory = hookMemory;

    cached = YES;
    available = YES;

    return available;
}

static void *libsubstitute_handle = NULL;
static void (*substitute_hookFunction)(void *, void *, void **) = NULL;
static void (*substitute_hookMessageEx)(Class, SEL, void *, void **) = NULL;
static void *(*substitute_getImageByName)(const char *) = NULL;
static void *(*substitute_findSymbol)(void *, const char *) = NULL;
static void (*substitute_hookMemory)(void *, const void *, size_t) = NULL;

// Native libsubstitute API, preferred over the MS-compatible shims when present.
static int (*fn_substitute_hook_functions)(const struct substitute_function_hook *, size_t, struct substitute_function_hook_record **, int) = NULL;
static int (*fn_substitute_hook_objc_message)(Class, SEL, void *, void *, bool *) = NULL;
static struct substitute_image *(*fn_substitute_open_image)(const char *) = NULL;
static void (*fn_substitute_close_image)(struct substitute_image *) = NULL;
static int (*fn_substitute_find_private_syms)(struct substitute_image *, const char **, void **, size_t) = NULL;
static void *(*fn_substitute_sym_to_ptr)(struct substitute_image *, substitute_sym *) = NULL;
static int (*fn_substitute_interpose_imports)(const struct substitute_image *, const struct substitute_import_hook *, size_t, struct substitute_import_hook_record **, int) = NULL;
static BOOL substitute_native_available = NO;

static void *resolve_ms_symbol(void *handle, const char *name, const char *fallback) {
    void *symbol = dlsym(handle, name);

    if(!symbol && fallback) {
        symbol = dlsym(handle, fallback);
    }

    return symbol;
}

// Only successful probes are cached: if dlopen fails, a later call retries
// (the engine may appear after HookKit loads).
BOOL substitute_available(void) {
    static BOOL cached = NO;
    static BOOL available = NO;

    if(cached) {
        return available;
    }

    NSString *jbPath = HKJBPath(@"/usr/lib/libsubstitute.0.dylib");

    if(!jbPath) {
        return NO;
    }

    void *handle = dlopen([jbPath fileSystemRepresentation], RTLD_LAZY);

    if(!handle) {
        return NO;
    }

    // Resolve into locals first: the globals are published only after the
    // ENTIRE required symbol set is present, so an incomplete library can
    // never leave half-populated function pointers behind.
    void (*hookFunction)(void *, void *, void **) = (void (*)(void *, void *, void **))resolve_ms_symbol(handle, "MSHookFunction", "SubHookFunction");
    void (*hookMessageEx)(Class, SEL, void *, void **) = (void (*)(Class, SEL, void *, void **))resolve_ms_symbol(handle, "MSHookMessageEx", "SubHookMessageEx");
    void *(*getImageByName)(const char *) = (void *(*)(const char *))resolve_ms_symbol(handle, "MSGetImageByName", "SubGetImageByName");
    void *(*findSymbol)(void *, const char *) = (void *(*)(void *, const char *))resolve_ms_symbol(handle, "MSFindSymbol", "SubFindSymbol");
    void (*hookMemory)(void *, const void *, size_t) = (void (*)(void *, const void *, size_t))resolve_ms_symbol(handle, "MSHookMemory", "SubHookMemory");

    int (*hookFunctions)(const struct substitute_function_hook *, size_t, struct substitute_function_hook_record **, int) = (int (*)(const struct substitute_function_hook *, size_t, struct substitute_function_hook_record **, int))dlsym(handle, "substitute_hook_functions");
    int (*hookObjcMessage)(Class, SEL, void *, void *, bool *) = (int (*)(Class, SEL, void *, void *, bool *))dlsym(handle, "substitute_hook_objc_message");
    struct substitute_image *(*openImage)(const char *) = (struct substitute_image *(*)(const char *))dlsym(handle, "substitute_open_image");
    void (*closeImage)(struct substitute_image *) = (void (*)(struct substitute_image *))dlsym(handle, "substitute_close_image");
    int (*findPrivateSyms)(struct substitute_image *, const char **, void **, size_t) = (int (*)(struct substitute_image *, const char **, void **, size_t))dlsym(handle, "substitute_find_private_syms");
    void *(*symToPtr)(struct substitute_image *, substitute_sym *) = (void *(*)(struct substitute_image *, substitute_sym *))dlsym(handle, "substitute_sym_to_ptr");
    int (*interposeImports)(const struct substitute_image *, const struct substitute_import_hook *, size_t, struct substitute_import_hook_record **, int) = (int (*)(const struct substitute_image *, const struct substitute_import_hook *, size_t, struct substitute_import_hook_record **, int))dlsym(handle, "substitute_interpose_imports");

    BOOL nativeAvailable = hookFunctions && hookObjcMessage
        && openImage && closeImage
        && findPrivateSyms && symToPtr;

    // ABI-incomplete (neither the MS-compatible shim set nor the native set
    // is fully present): drop the handle and stay uncached so a later probe
    // genuinely retries. Nothing was published.
    if(!((hookFunction && hookMessageEx && getImageByName && findSymbol)
            || nativeAvailable)) {
        dlclose(handle);
        return NO;
    }

    libsubstitute_handle = handle;
    substitute_hookFunction = hookFunction;
    substitute_hookMessageEx = hookMessageEx;
    substitute_getImageByName = getImageByName;
    substitute_findSymbol = findSymbol;
    substitute_hookMemory = hookMemory;

    fn_substitute_hook_functions = hookFunctions;
    fn_substitute_hook_objc_message = hookObjcMessage;
    fn_substitute_open_image = openImage;
    fn_substitute_close_image = closeImage;
    fn_substitute_find_private_syms = findPrivateSyms;
    fn_substitute_sym_to_ptr = symToPtr;
    fn_substitute_interpose_imports = interposeImports;
    substitute_native_available = nativeAvailable;

    cached = YES;
    available = YES;

    return available;
}

#pragma mark - HKMSBackend

@implementation HKMSBackend
- (instancetype)initWithHookFunction:(void (*)(void *, void *, void **))hookFunction
                      hookMessageEx:(void (*)(Class, SEL, void *, void **))hookMessageEx
                    getImageByName:(void *(*)(const char *))getImageByName
                       findSymbol:(void *(*)(void *, const char *))findSymbol {
    if((self = [super init])) {
        msHookFunction = hookFunction;
        msHookMessageEx = hookMessageEx;
        msGetImageByName = getImageByName;
        msFindSymbol = findSymbol;
        _lastErrno = 0;
    }

    return self;
}

- (BOOL)batchingSupported {
    return NO;
}

- (BOOL)supportsHookKind:(HKHookKind)kind {
    return kind == HKHookKindMessage || kind == HKHookKindFunction;
}

- (int)lastErrno {
    return _lastErrno;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    if(!class_getInstanceMethod(objcClass, selector) && !class_getClassMethod(objcClass, selector)) {
        _lastErrno = 0;
        return HK_ERR_NOT_SUPPORTED;
    }

    // MSHookMessageEx is void and its success is unverifiable — the hook is
    // submitted, unverified (Substrate API limitation). Some Substrate builds
    // signal failure through errno.
    errno = 0;
    msHookMessageEx(objcClass, selector, replacement, old_ptr);
    _lastErrno = errno;
    return errno ? HK_ERR : HK_OK;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    // MSHookFunction is void — submitted, unverified; some Substrate builds
    // signal failure through errno.
    errno = 0;
    msHookFunction(function, replacement, old_ptr);
    _lastErrno = errno;
    return errno ? HK_ERR : HK_OK;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    _lastErrno = 0;
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks {
    // nothing pending: hooks are applied at hook time
    return HK_OK;
}

- (HKImageRef)openImage:(NSString *)path {
    return (HKImageRef)msGetImageByName([path fileSystemRepresentation]);
}

- (void)closeImage:(HKImageRef)image {
    // MSCloseImage is not actually exported by either library at runtime
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    const char *symbol = [symbolName UTF8String];

    if(image) {
        return msFindSymbol((void *)image, symbol);
    }

    // image == NULL: iterate all loaded dyld images
    return hk_search_loaded_images(^void *(const char *image_name) {
        void *imageHandle = msGetImageByName(image_name);
        return imageHandle ? msFindSymbol(imageHandle, symbol) : NULL;
    });
}
@end

#pragma mark - HKSubstrateBackend

@implementation HKSubstrateBackend
- (instancetype)init {
    return [super initWithHookFunction:substrate_hookFunction hookMessageEx:substrate_hookMessageEx getImageByName:substrate_getImageByName findSymbol:substrate_findSymbol];
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    if(substrate_hookMemory) {
        _lastErrno = 0;
        substrate_hookMemory(target, data, size);
        return HK_OK;
    }

    _lastErrno = 0;
    return HK_ERR_NOT_SUPPORTED;
}
@end

#pragma mark - Substitute error classification

// Maps a native libsubstitute error code to the hookkit status. Pure: no
// state, just the code table. Shared by hookFunction: and hookMessageInClass:.
//
// Capability misses mean the hook was NOT applied — the function's shape or
// the selector's absence make this technique unusable, which is what
// HK_ERR_NOT_SUPPORTED reports so callers can switch hooking techniques.
//
// Everything else (OOM, VM, NOT_ON_MAIN_THREAD, UNEXPECTED_PC_ON_OTHER_THREAD
// [the hooks were otherwise completed], ADJUSTING_THREADS, or any unknown or
// future code from a newer installed libsubstitute than the vendored header)
// is terminal: the hook may already be applied, so it must never be retried.
// The default fails closed to HK_ERR.
//
// The taxonomy itself lives in Internal/HKSubstituteErrors.c (pure C, shared
// with the host-side unit test) — the mapping here is just its status form.
static hookkit_status_t substitute_error_to_status(int err) {
    switch(hk_substitute_err_classify(err)) {
        case HKSubErrOK:
            return HK_OK;

        case HKSubErrCapabilityMiss:
            return HK_ERR_NOT_SUPPORTED;

        default:
            return HK_ERR;
    }
}

#pragma mark - HKSubstituteBackend

@implementation HKSubstituteBackend
- (instancetype)init {
    return [super initWithHookFunction:substitute_hookFunction hookMessageEx:substitute_hookMessageEx getImageByName:substitute_getImageByName findSymbol:substitute_findSymbol];
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    if(!substitute_native_available) {
        return [super hookMessageInClass:objcClass withSelector:selector withReplacement:replacement outOldPtr:old_ptr];
    }

    if(!class_getInstanceMethod(objcClass, selector) && !class_getClassMethod(objcClass, selector)) {
        _lastErrno = 0;
        return HK_ERR_NOT_SUPPORTED;
    }

    int result = fn_substitute_hook_objc_message(objcClass, selector, replacement, old_ptr, NULL);
    _lastErrno = result;
    return substitute_error_to_status(result);
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    if(!substitute_native_available) {
        return [super hookFunction:function withReplacement:replacement outOldPtr:old_ptr];
    }

    struct substitute_function_hook hook = {
        function, replacement, old_ptr, 0
    };

    int result = fn_substitute_hook_functions(&hook, 1, NULL, 0);
    _lastErrno = result;

    if(result == SUBSTITUTE_OK) {
        return HK_OK;
    }

    // GOT/PLT interposition fallback: on iOS 16.2+ the AMFI/APT policy
    // changes broke executable-code patching, so substitute_hook_functions
    // fails on functions it could otherwise hook. The fallback fires ONLY
    // for the five capability-miss codes — substitute reported it could not
    // patch the function, so nothing was written and interposing is safe.
    // Any other code (OOM, VM, NOT_ON_MAIN_THREAD, UNEXPECTED_PC_ON_OTHER_
    // THREAD, ADJUSTING_THREADS, or unknown/future) means the hook may
    // already be applied — retrying with interposition could double-hook.
    // Same taxonomy as the status mapping above (Internal/HKSubstituteErrors.c).
    if(fn_substitute_interpose_imports && hk_substitute_err_is_retryable(result)) {
        Dl_info info;

#if __has_feature(ptrauth_calls)
        function = ptrauth_strip(function, ptrauth_key_asia);
#endif

        if(dladdr(function, &info) && info.dli_sname) {
            // Fresh zeroed out-cell: substitute may have written old_ptr
            // while preparing the failed inline hook — never reuse a
            // possibly-written cell.
            void *interposedOld = NULL;

            struct substitute_import_hook ih = {
                .name = info.dli_sname,
                .replacement = replacement,
                .old_ptr = &interposedOld,
                .options = 0
            };

            int interposeResult = fn_substitute_interpose_imports(NULL, &ih, 1, NULL, 0);
            _lastErrno = interposeResult;

            // Publish the interpose result's old value only on success.
            if(interposeResult == SUBSTITUTE_OK) {
                if(old_ptr) {
                    *old_ptr = interposedOld;
                }

                return HK_OK;
            }
        }
    }

    return substitute_error_to_status(result);
}

- (HKImageRef)openImage:(NSString *)path {
    if(!substitute_native_available) {
        return [super openImage:path];
    }

    return (HKImageRef)fn_substitute_open_image([path fileSystemRepresentation]);
}

- (void)closeImage:(HKImageRef)image {
    if(substitute_native_available && image) {
        fn_substitute_close_image((struct substitute_image *)image);
        return;
    }

    [super closeImage:image];
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    if(!substitute_native_available) {
        return [super findSymbolInImage:image symbolName:symbolName];
    }

    const char *symbol = [symbolName UTF8String];

    if(image) {
        void *sym = NULL;

        if(fn_substitute_find_private_syms((struct substitute_image *)image, &symbol, &sym, 1) == SUBSTITUTE_OK && sym) {
            return fn_substitute_sym_to_ptr((struct substitute_image *)image, (substitute_sym *)sym);
        }

        return NULL;
    }

    // image == NULL: iterate all loaded dyld images
    return hk_search_loaded_images(^void *(const char *image_name) {
        struct substitute_image *subImage = fn_substitute_open_image(image_name);

        if(!subImage) {
            return NULL;
        }

        // the block captures `symbol` as const, so pass a mutable copy
        const char *probe = symbol;
        void *sym = NULL;
        void *result = NULL;

        if(fn_substitute_find_private_syms(subImage, &probe, &sym, 1) == SUBSTITUTE_OK && sym) {
            result = fn_substitute_sym_to_ptr(subImage, (substitute_sym *)sym);
        }

        fn_substitute_close_image(subImage);
        return result;
    });
}

// Substitute backend memory hooking: the MS-compatible shim path resolves
// SubHookMemory on Substitute (the native API has no separate memory hook).
- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    if(substitute_hookMemory) {
        _lastErrno = 0;
        substitute_hookMemory(target, data, size);
        return HK_OK;
    }

    _lastErrno = 0;
    return HK_ERR_NOT_SUPPORTED;
}
@end