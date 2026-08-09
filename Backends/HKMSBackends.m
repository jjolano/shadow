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
    return result == SUBSTITUTE_OK ? HK_OK : HK_ERR;
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

    return HK_ERR;
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