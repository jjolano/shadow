#import "Internal/HKBackendInternal.h"

#import <dlfcn.h>
#import <errno.h>
#import <objc/runtime.h>

#import "vendor/substrate/substrate.h"
#import "vendor/substitute/substitute.h"

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

    substrate_handle = dlopen([jbPath fileSystemRepresentation], RTLD_LAZY);

    if(!substrate_handle) {
        return NO;
    }

    substrate_hookFunction = (void (*)(void *, void *, void **))dlsym(substrate_handle, "MSHookFunction");
    substrate_hookMessageEx = (void (*)(Class, SEL, void *, void **))dlsym(substrate_handle, "MSHookMessageEx");
    substrate_getImageByName = (void *(*)(const char *))dlsym(substrate_handle, "MSGetImageByName");
    substrate_findSymbol = (void *(*)(void *, const char *))dlsym(substrate_handle, "MSFindSymbol");
    substrate_hookMemory = (void (*)(void *, const void *, size_t))dlsym(substrate_handle, "MSHookMemory");

    available = substrate_hookFunction && substrate_hookMessageEx
        && substrate_getImageByName && substrate_findSymbol;
    cached = YES;

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

    libsubstitute_handle = dlopen([jbPath fileSystemRepresentation], RTLD_LAZY);

    if(!libsubstitute_handle) {
        return NO;
    }

    substitute_hookFunction = (void (*)(void *, void *, void **))resolve_ms_symbol(libsubstitute_handle, "MSHookFunction", "SubHookFunction");
    substitute_hookMessageEx = (void (*)(Class, SEL, void *, void **))resolve_ms_symbol(libsubstitute_handle, "MSHookMessageEx", "SubHookMessageEx");
    substitute_getImageByName = (void *(*)(const char *))resolve_ms_symbol(libsubstitute_handle, "MSGetImageByName", "SubGetImageByName");
    substitute_findSymbol = (void *(*)(void *, const char *))resolve_ms_symbol(libsubstitute_handle, "MSFindSymbol", "SubFindSymbol");
    substitute_hookMemory = (void (*)(void *, const void *, size_t))resolve_ms_symbol(libsubstitute_handle, "MSHookMemory", "SubHookMemory");

    fn_substitute_hook_functions = (int (*)(const struct substitute_function_hook *, size_t, struct substitute_function_hook_record **, int))dlsym(libsubstitute_handle, "substitute_hook_functions");
    fn_substitute_hook_objc_message = (int (*)(Class, SEL, void *, void *, bool *))dlsym(libsubstitute_handle, "substitute_hook_objc_message");
    fn_substitute_open_image = (struct substitute_image *(*)(const char *))dlsym(libsubstitute_handle, "substitute_open_image");
    fn_substitute_close_image = (void (*)(struct substitute_image *))dlsym(libsubstitute_handle, "substitute_close_image");
    fn_substitute_find_private_syms = (int (*)(struct substitute_image *, const char **, void **, size_t))dlsym(libsubstitute_handle, "substitute_find_private_syms");
    fn_substitute_sym_to_ptr = (void *(*)(struct substitute_image *, substitute_sym *))dlsym(libsubstitute_handle, "substitute_sym_to_ptr");
    fn_substitute_interpose_imports = (int (*)(const struct substitute_image *, const struct substitute_import_hook *, size_t, struct substitute_import_hook_record **, int))dlsym(libsubstitute_handle, "substitute_interpose_imports");

    substitute_native_available = fn_substitute_hook_functions && fn_substitute_hook_objc_message
        && fn_substitute_open_image && fn_substitute_close_image
        && fn_substitute_find_private_syms && fn_substitute_sym_to_ptr;

    available = (substitute_hookFunction && substitute_hookMessageEx
        && substitute_getImageByName && substitute_findSymbol)
        || substitute_native_available;

    cached = YES;

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
static hookkit_status_t substitute_error_to_status(int err) {
    switch(err) {
        case SUBSTITUTE_OK:
            return HK_OK;

        case SUBSTITUTE_ERR_FUNC_TOO_SHORT:
        case SUBSTITUTE_ERR_FUNC_BAD_INSN_AT_START:
        case SUBSTITUTE_ERR_FUNC_CALLS_AT_START:
        case SUBSTITUTE_ERR_FUNC_JUMPS_TO_START:
        case SUBSTITUTE_ERR_OUT_OF_RANGE:
        case SUBSTITUTE_ERR_NO_SUCH_SELECTOR:
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
    if(fn_substitute_interpose_imports
        && (result == SUBSTITUTE_ERR_FUNC_TOO_SHORT
            || result == SUBSTITUTE_ERR_FUNC_BAD_INSN_AT_START
            || result == SUBSTITUTE_ERR_FUNC_CALLS_AT_START
            || result == SUBSTITUTE_ERR_FUNC_JUMPS_TO_START
            || result == SUBSTITUTE_ERR_OUT_OF_RANGE)) {
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