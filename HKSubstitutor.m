#import <HookKit/Compat.h>
#import <RootBridge.h>

#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import <errno.h>
#import <string.h>
#import <stdlib.h>

#import "vendor/libhooker/libhooker.h"
#import "vendor/libhooker/libblackjack.h"
#import "vendor/fishhook/fishhook.h"
#if __has_include(<ptrauth.h>)
#import <ptrauth.h>
#endif
#import "vendor/substrate/substrate.h"
#import "vendor/substitute/substitute.h"

// Dobby: vendored static lib with arm64/arm64e slices only; the header is
// plain C and safe to include, but the backend class below is arch-gated too
// so armv7 builds never reference DobbyHook/DobbyCodePatch at link time.
#if defined(__arm64__) || defined(__arm64e__)
#include "dobby/dobby.h"
#endif

#import "native/hk_native.h"

#pragma mark - libhooker (ElleKit) runtime resolution

// libhooker is dlopen'd at runtime so that HookKit loads cleanly without ElleKit installed.
// fishhook is compiled in and always available.
static void* libhooker_handle = NULL;
static enum LIBHOOKER_ERR (*fn_LBHookMessage)(Class, SEL, void *, void *) = NULL;
static int (*fn_LHHookFunctions)(const struct LHFunctionHook *, int) = NULL;
static int (*fn_LHPatchMemory)(const struct LHMemoryPatch *, int) = NULL;
static struct libhooker_image *(*fn_LHOpenImage)(const char *) = NULL;
static void (*fn_LHCloseImage)(struct libhooker_image *) = NULL;
static bool (*fn_LHFindSymbols)(struct libhooker_image *, const char **, void **, size_t) = NULL;

// Only successful probes are cached: if dlopen fails, a later call retries
// (the engine may appear after HookKit loads).
static BOOL libhooker_available(void) {
    static BOOL cached = NO;
    static BOOL available = NO;

    if(cached) {
        return available;
    }

    libhooker_handle = dlopen([[RootBridge getJBPath:@"/usr/lib/libhooker.dylib"] fileSystemRepresentation], RTLD_LAZY);

    if(!libhooker_handle) {
        return NO;
    }

    fn_LBHookMessage = (enum LIBHOOKER_ERR (*)(Class, SEL, void *, void *))dlsym(libhooker_handle, "LBHookMessage");
    fn_LHHookFunctions = (int (*)(const struct LHFunctionHook *, int))dlsym(libhooker_handle, "LHHookFunctions");
    fn_LHPatchMemory = (int (*)(const struct LHMemoryPatch *, int))dlsym(libhooker_handle, "LHPatchMemory");
    fn_LHOpenImage = (struct libhooker_image *(*)(const char *))dlsym(libhooker_handle, "LHOpenImage");
    fn_LHCloseImage = (void (*)(struct libhooker_image *))dlsym(libhooker_handle, "LHCloseImage");
    fn_LHFindSymbols = (bool (*)(struct libhooker_image *, const char **, void **, size_t))dlsym(libhooker_handle, "LHFindSymbols");

    available = fn_LBHookMessage && fn_LHHookFunctions && fn_LHPatchMemory
        && fn_LHOpenImage && fn_LHCloseImage && fn_LHFindSymbols;
    cached = YES;

    return available;
}

#pragma mark - Cydia Substrate / Substitute (MS-compatible API) runtime resolution

// Both libraries expose the classic Cydia Substrate C API. Cydia Substrate
// exports the MS* symbols directly; libsubstitute exports them under MS*
// (older versions) or Sub* (newer versions) names, so try both.
static void *substrate_handle = NULL;
static void (*substrate_hookFunction)(void *, void *, void **) = NULL;
static void (*substrate_hookMessageEx)(Class, SEL, void *, void **) = NULL;
static void *(*substrate_getImageByName)(const char *) = NULL;
static void *(*substrate_findSymbol)(void *, const char *) = NULL;

static BOOL substrate_available(void) {
    static BOOL cached = NO;
    static BOOL available = NO;

    if(cached) {
        return available;
    }

    substrate_handle = dlopen([[RootBridge getJBPath:@"/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate"] fileSystemRepresentation], RTLD_LAZY);

    if(!substrate_handle) {
        return NO;
    }

    substrate_hookFunction = (void (*)(void *, void *, void **))dlsym(substrate_handle, "MSHookFunction");
    substrate_hookMessageEx = (void (*)(Class, SEL, void *, void **))dlsym(substrate_handle, "MSHookMessageEx");
    substrate_getImageByName = (void *(*)(const char *))dlsym(substrate_handle, "MSGetImageByName");
    substrate_findSymbol = (void *(*)(void *, const char *))dlsym(substrate_handle, "MSFindSymbol");

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

static BOOL substitute_available(void) {
    static BOOL cached = NO;
    static BOOL available = NO;

    if(cached) {
        return available;
    }

    libsubstitute_handle = dlopen([[RootBridge getJBPath:@"/usr/lib/libsubstitute.0.dylib"] fileSystemRepresentation], RTLD_LAZY);

    if(!libsubstitute_handle) {
        return NO;
    }

    substitute_hookFunction = (void (*)(void *, void *, void **))resolve_ms_symbol(libsubstitute_handle, "MSHookFunction", "SubHookFunction");
    substitute_hookMessageEx = (void (*)(Class, SEL, void *, void **))resolve_ms_symbol(libsubstitute_handle, "MSHookMessageEx", "SubHookMessageEx");
    substitute_getImageByName = (void *(*)(const char *))resolve_ms_symbol(libsubstitute_handle, "MSGetImageByName", "SubGetImageByName");
    substitute_findSymbol = (void *(*)(void *, const char *))resolve_ms_symbol(libsubstitute_handle, "MSFindSymbol", "SubFindSymbol");

    available = substitute_hookFunction && substitute_hookMessageEx
        && substitute_getImageByName && substitute_findSymbol;

    fn_substitute_hook_functions = (int (*)(const struct substitute_function_hook *, size_t, struct substitute_function_hook_record **, int))dlsym(libsubstitute_handle, "substitute_hook_functions");
    fn_substitute_hook_objc_message = (int (*)(Class, SEL, void *, void *, bool *))dlsym(libsubstitute_handle, "substitute_hook_objc_message");
    fn_substitute_open_image = (struct substitute_image *(*)(const char *))dlsym(libsubstitute_handle, "substitute_open_image");
    fn_substitute_close_image = (void (*)(struct substitute_image *))dlsym(libsubstitute_handle, "substitute_close_image");
    fn_substitute_find_private_syms = (int (*)(struct substitute_image *, const char **, void **, size_t))dlsym(libsubstitute_handle, "substitute_find_private_syms");
    fn_substitute_sym_to_ptr = (void *(*)(struct substitute_image *, substitute_sym *))dlsym(libsubstitute_handle, "substitute_sym_to_ptr");

    substitute_native_available = fn_substitute_hook_functions && fn_substitute_hook_objc_message
        && fn_substitute_open_image && fn_substitute_close_image
        && fn_substitute_find_private_syms && fn_substitute_sym_to_ptr;

    cached = YES;

    return available;
}

#pragma mark - Hook operations

typedef NS_ENUM(int, HKHookKind) {
    HKHookKindMessage,
    HKHookKindFunction,
    HKHookKindMemory
};

// A deferred hook. Storage that the backend may retain (memory patch bytes,
// the out-cell written by the backend) is owned here; callerOrig is borrowed
// and only used for the post-execution copy in executeHooks.
@interface HKHookOperation : NSObject {
@public
    HKHookKind kind;
    Class objcClass;
    SEL selector;
    void *function;
    void *replacement;
    void *origValue;    // owned out-cell the backend writes at execute time
    void **callerOrig;  // borrowed caller out-pointer; copied once, then cleared
    void *target;
    NSData *data;       // owned copy of the memory patch bytes
    size_t size;
    BOOL succeeded;
}
@end

@implementation HKHookOperation
@end

// Shared by every backend that scans for a symbol with no image specified.
static void *hk_search_loaded_images(void *(^probe)(const char *imageName)) {
    int count = _dyld_image_count();

    for(int i = 0; i < count; i++) {
        const char *image_name = _dyld_get_image_name(i);

        if(!image_name) {
            continue;
        }

        void *found = probe(image_name);

        if(found) {
            return found;
        }
    }

    return NULL;
}

static hookkit_status_t hk_batch_status(int succeeded, int total) {
    if(succeeded < total) {
        NSLog(@"[HookKit] warning: successfully hooked less than expected (%d/%d)", succeeded, total);
    }

    if(succeeded == total) {
        return HK_OK;
    }

    return succeeded > 0 ? HK_ERR_PARTIAL : HK_ERR;
}

#pragma mark - Backends

@protocol HKSubstitutorBackend <NSObject>
@property (nonatomic, readonly) BOOL batchingSupported;
@property (nonatomic, readonly) int lastErrno;

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;
- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;
- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size;
- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks;

- (HKImageRef)openImage:(NSString *)path;
- (void)closeImage:(HKImageRef)image;
- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName;
@end

// ElleKit backend: libhooker API, resolved at runtime via dlopen/dlsym.
@interface HKElleKitBackend : NSObject <HKSubstitutorBackend> {
    int _lastErrno;
}
@end

@implementation HKElleKitBackend
- (BOOL)batchingSupported {
    return YES;
}

- (int)lastErrno {
    return _lastErrno;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    enum LIBHOOKER_ERR result = fn_LBHookMessage(objcClass, selector, replacement, (void *)old_ptr);
    _lastErrno = result;
    return result == LIBHOOKER_OK ? HK_OK : HK_ERR;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    struct LHFunctionHook hook = {
        function, replacement, (void *)old_ptr, NULL
    };

    int result = fn_LHHookFunctions(&hook, 1);
    _lastErrno = result;
    return result == 1 ? HK_OK : HK_ERR;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    struct LHMemoryPatch patch = {
        target, data, size, 0
    };

    int result = fn_LHPatchMemory(&patch, 1);
    _lastErrno = result;
    return result == 1 ? HK_OK : HK_ERR;
}

- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks {
    int total = (int)[hooks count];
    int succeeded = 0;
    _lastErrno = 0;

    NSMutableData *functionHooks = [NSMutableData new];
    NSMutableData *memoryHooks = [NSMutableData new];
    NSMutableArray<HKHookOperation *> *functionOps = [NSMutableArray new];
    NSMutableArray<HKHookOperation *> *memoryOps = [NSMutableArray new];

    for(HKHookOperation *hook in hooks) {
        switch(hook->kind) {
            case HKHookKindMessage: {
                enum LIBHOOKER_ERR result = fn_LBHookMessage(hook->objcClass, hook->selector, hook->replacement, (void *)&hook->origValue);
                _lastErrno = result;

                if(result == LIBHOOKER_OK) {
                    hook->succeeded = YES;
                    succeeded += 1;
                }

                break;
            }

            case HKHookKindFunction: {
                struct LHFunctionHook lh = {
                    hook->function, hook->replacement, &hook->origValue, NULL
                };

                [functionHooks appendBytes:&lh length:sizeof(struct LHFunctionHook)];
                [functionOps addObject:hook];
                break;
            }

            case HKHookKindMemory: {
                struct LHMemoryPatch lh = {
                    hook->target, [hook->data bytes], hook->size, 0
                };

                [memoryHooks appendBytes:&lh length:sizeof(struct LHMemoryPatch)];
                [memoryOps addObject:hook];
                break;
            }
        }
    }

    if([functionHooks length]) {
        int count = (int)([functionHooks length] / sizeof(struct LHFunctionHook));
        int result = fn_LHHookFunctions([functionHooks mutableBytes], count);
        _lastErrno = result;

        if(result < count) {
            NSLog(@"[HKElleKit] warning: batch LHHookFunctions retval less than expected (%d/%lu)", result, (unsigned long)([functionHooks length] / sizeof(struct LHFunctionHook)));
        }

        // libhooker applies hooks in order and stops at the first failure,
        // so the first `result` ops succeeded.
        for(int i = 0; i < result; i++) {
            functionOps[i]->succeeded = YES;
        }

        succeeded += result;
    }

    if([memoryHooks length]) {
        int count = (int)([memoryHooks length] / sizeof(struct LHMemoryPatch));
        int result = fn_LHPatchMemory([memoryHooks mutableBytes], count);
        _lastErrno = result;

        if(result < count) {
            NSLog(@"[HKElleKit] warning: batch LHPatchMemory retval less than expected (%d/%lu)", result, (unsigned long)([memoryHooks length] / sizeof(struct LHMemoryPatch)));
        }

        for(int i = 0; i < result; i++) {
            memoryOps[i]->succeeded = YES;
        }

        succeeded += result;
    }

    return hk_batch_status(succeeded, total);
}

- (HKImageRef)openImage:(NSString *)path {
    return (HKImageRef)fn_LHOpenImage([path fileSystemRepresentation]);
}

- (void)closeImage:(HKImageRef)image {
    if(image) {
        fn_LHCloseImage((struct libhooker_image *)image);
    }
}

// ElleKit expects C symbols with a leading underscore; Substrate-style names
// come in without one. Try the name as given, then with '_' prepended.
- (void *)findSymbol:(const char *)name inImage:(struct libhooker_image *)image {
    if(!image || !name || !name[0]) {
        return NULL;
    }

    void *result = NULL;
    const char *probe = name;

    if(fn_LHFindSymbols(image, &probe, &result, 1) && result) {
        return result;
    }

    if(name[0] == '_') {
        return NULL;
    }

    char *prefixed = malloc(strlen(name) + 2);
    prefixed[0] = '_';
    strcpy(prefixed + 1, name);

    result = NULL;
    probe = prefixed;
    fn_LHFindSymbols(image, &probe, &result, 1);
    free(prefixed);

    return result;
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    const char *symbol = [symbolName UTF8String];

    if(image) {
        return [self findSymbol:symbol inImage:(struct libhooker_image *)image];
    }

    // image == NULL: iterate all loaded dyld images
    return hk_search_loaded_images(^void *(const char *image_name) {
        struct libhooker_image *libhookerImage = fn_LHOpenImage(image_name);

        if(!libhookerImage) {
            // no handle, no symbol lookup: skip this image
            return NULL;
        }

        void *result = [self findSymbol:symbol inImage:libhookerImage];
        fn_LHCloseImage(libhookerImage);
        return result;
    });
}
@end

// Shared implementation for backends exposing the Cydia Substrate C API.
// Batching is not supported: hooks are applied immediately at hook time, and
// memory patches are not supported.
@interface HKMSBackend : NSObject <HKSubstitutorBackend> {
@protected
    void (*msHookFunction)(void *, void *, void **);
    void (*msHookMessageEx)(Class, SEL, void *, void **);
    void *(*msGetImageByName)(const char *);
    void *(*msFindSymbol)(void *, const char *);
    int _lastErrno;
}

- (instancetype)initWithHookFunction:(void (*)(void *, void *, void **))hookFunction
                      hookMessageEx:(void (*)(Class, SEL, void *, void **))hookMessageEx
                    getImageByName:(void *(*)(const char *))getImageByName
                       findSymbol:(void *(*)(void *, const char *))findSymbol;
@end

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

// Cydia Substrate backend: unc0ver and 32-bit jailbreaks.
@interface HKSubstrateBackend : HKMSBackend
@end

@implementation HKSubstrateBackend
- (instancetype)init {
    return [super initWithHookFunction:substrate_hookFunction hookMessageEx:substrate_hookMessageEx getImageByName:substrate_getImageByName findSymbol:substrate_findSymbol];
}
@end

// Substitute backend: checkra1n-classic (Substitute-based jailbreaks).
// Uses libsubstitute's native API when available, otherwise the MS-compatible
// path (which also fixes the leak of Substitute image handles).
@interface HKSubstituteBackend : HKMSBackend
@end

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
    return result == SUBSTITUTE_OK ? HK_OK : HK_ERR;
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
@end

// fishhook backend: rebind_symbols for C functions; dlsym/dyld iteration for symbol lookup.
// Batching is not supported: function hooks are applied immediately, and ObjC message
// hooks and memory patches are not supported at all.
@interface HKFishhookBackend : NSObject <HKSubstitutorBackend>
@end

// fishhook's rebind_symbols retains the name and replaced pointers of each
// struct rebinding for ALL future dlopen events, so they must outlive
// hookFunction:. Each hook is therefore kept in a process-lifetime store
// forever — per-hook, bounded. Deliberate: fishhook writes the original
// through these cells on every future image load. Guarded because
// hookFunction: may be called from multiple threads (fishhook's own list is
// locked internally; the ObjC store is not).
@interface HKFishhookRebinding : NSObject {
@public
    char *name;
    void **origCell;
}
@end

@implementation HKFishhookRebinding
@end

static NSMutableArray<HKFishhookRebinding *> *fishhookRebindingStore(void) {
    static NSMutableArray *store = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        store = [NSMutableArray new];
    });

    return store;
}

@implementation HKFishhookBackend {
    int _lastErrno;
}
- (BOOL)batchingSupported {
    return NO;
}

- (int)lastErrno {
    return _lastErrno;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    _lastErrno = 0;

    Dl_info info;

#if __has_feature(ptrauth_calls)
    // The caller may pass a signed function pointer (arm64e function
    // pointers are signed with asia/div-0 by the ABI). dladdr and the
    // dli_saddr comparison below work on the raw address, so strip first.
    function = ptrauth_strip(function, ptrauth_key_asia);
#endif

    if(!(dladdr(function, &info) && info.dli_sname && info.dli_saddr == function)) {
        // fishhook rebinds by exported symbol name; private/interior
        // addresses are not rebindable
        return HK_ERR_NOT_SUPPORTED;
    }

    HKFishhookRebinding *owned = [HKFishhookRebinding new];
    owned->name = strdup(info.dli_sname);
    owned->origCell = calloc(1, sizeof(void *));

    struct rebinding rebinding = {
        owned->name, replacement, owned->origCell
    };

    size_t matched = 0;
    int result = rebind_symbols_checked(&rebinding, 1, &matched);

    if(result != 0) {
        free(owned->name);
        free(owned->origCell);
        return HK_ERR;
    }

    if(matched == 0) {
        // The symbol is exported (dladdr found it) but no loaded image
        // references it through an indirect symbol pointer, so the rebinding
        // is a silent no-op today. fishhook retains it for future image
        // loads, so keep the cells alive in the store, but report the no-op
        // honestly instead of pretending the hook took effect.
        NSLog(@"[HookKit] fishhook: symbol '%s' is not referenced by any loaded image; hook is a no-op", owned->name);

        @synchronized(fishhookRebindingStore()) {
            [fishhookRebindingStore() addObject:owned];
        }

        return HK_ERR_NOT_SUPPORTED;
    }

    // Copy synchronously; the caller's pointer is used only here and never
    // passed to rebind_symbols (which would retain it past this call).
    if(old_ptr) {
        *old_ptr = *(owned->origCell);
    }

    @synchronized(fishhookRebindingStore()) {
        [fishhookRebindingStore() addObject:owned];
    }

    return HK_OK;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks {
    // nothing pending: function hooks are applied at hookFunction: time
    return HK_OK;
}

- (HKImageRef)openImage:(NSString *)path {
    // RTLD_NOLOAD: inspect-only, never loads the dylib — matches the MS/ElleKit
    // contract that openImage does not load images
    return (HKImageRef)dlopen([path fileSystemRepresentation], RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD);
}

- (void)closeImage:(HKImageRef)image {
    if(image) {
        dlclose((void *)image);
    }
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    const char *symbol = [symbolName UTF8String];

    if(image) {
        return dlsym((void *)image, symbol);
    }

    // image == NULL: search the default scope, then all loaded dyld images
    void *found = dlsym(RTLD_DEFAULT, symbol);

    if(found) {
        return found;
    }

    return hk_search_loaded_images(^void *(const char *image_name) {
        void *handle = dlopen(image_name, RTLD_LAZY | RTLD_NOLOAD);

        if(!handle) {
            return NULL;
        }

        void *result = dlsym(handle, symbol);
        dlclose(handle);
        return result;
    });
}
@end

// Native backend: HookKit's own engine, requiring no hooking library on the
// device. Never selected automatically — callers opt in with HK_LIB_NATIVE.
// See native/hk_native.h for the constraints.
@interface HKNativeBackend : NSObject <HKSubstitutorBackend>
@end

@implementation HKNativeBackend {
    int _lastErrno;
}

- (BOOL)batchingSupported {
    return YES;
}

- (int)lastErrno {
    return _lastErrno;
}

// Pure libobjc: no patching, no privileged memory, works wherever HookKit runs.
- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    _lastErrno = 0;

    Method method = class_getInstanceMethod(objcClass, selector);

    if(!method) {
        return HK_ERR_NOT_SUPPORTED;
    }

    IMP inherited = method_getImplementation(method);

    // class_getInstanceMethod walks superclasses, so the method may not belong
    // to this class. Adding it here leaves the superclass untouched and chains
    // to the implementation we would otherwise have inherited.
    if(class_addMethod(objcClass, selector, (IMP)replacement, method_getTypeEncoding(method))) {
        if(old_ptr) {
            *old_ptr = (void *)inherited;
        }

        return HK_OK;
    }

    IMP previous = method_setImplementation(method, (IMP)replacement);

    if(old_ptr) {
        *old_ptr = (void *)previous;
    }

    return HK_OK;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    void *orig = NULL;

    if(!hk_native_hook_function(function, replacement, &orig)) {
        _lastErrno = hk_native_last_error();
        return HK_ERR;
    }

    _lastErrno = 0;

    if(old_ptr) {
        *old_ptr = orig;
    }

    return HK_OK;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    if(!hk_native_patch_memory(target, data, size)) {
        _lastErrno = hk_native_last_error();
        return HK_ERR;
    }

    _lastErrno = 0;
    return HK_OK;
}

// No cross-hook batching to exploit — each patch is independent — but the
// protocol's batch path is still honoured so callers get uniform semantics.
- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks {
    int total = (int)[hooks count];
    int succeeded = 0;
    int failureErrno = 0;

    for(HKHookOperation *hook in hooks) {
        hookkit_status_t result = HK_ERR;

        switch(hook->kind) {
            case HKHookKindMessage:
                result = [self hookMessageInClass:hook->objcClass withSelector:hook->selector withReplacement:hook->replacement outOldPtr:&hook->origValue];
                break;

            case HKHookKindFunction:
                result = [self hookFunction:hook->function withReplacement:hook->replacement outOldPtr:&hook->origValue];
                break;

            case HKHookKindMemory:
                result = [self hookMemory:hook->target withData:[hook->data bytes] size:hook->size];
                break;
        }

        if(result == HK_OK) {
            hook->succeeded = YES;
            succeeded += 1;
        } else if(!failureErrno) {
            failureErrno = _lastErrno;
        }
    }

    _lastErrno = failureErrno;

    return hk_batch_status(succeeded, total);
}

- (HKImageRef)openImage:(NSString *)path {
    return (HKImageRef)hk_native_open_image([path fileSystemRepresentation]);
}

- (void)closeImage:(HKImageRef)image {
    if(image) {
        hk_native_close_image((hk_image *)image);
    }
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    const char *symbol = [symbolName UTF8String];

    if(image) {
        return hk_native_find_symbol((hk_image *)image, symbol);
    }

    // image == NULL: search the default scope, then all loaded dyld images
    void *found = dlsym(RTLD_DEFAULT, symbol);

    if(found) {
        return found;
    }

    return hk_search_loaded_images(^void *(const char *image_name) {
        hk_image *handle = hk_native_open_image(image_name);

        if(!handle) {
            return NULL;
        }

        void *result = hk_native_find_symbol(handle, symbol);
        hk_native_close_image(handle);
        return result;
    });
}
@end

// Dobby backend: inline hooking via the vendored Dobby static library
// (vendor/dobby). Hooks by address, so interior/private C functions work
// (unlike fishhook). No ObjC message hooking and no batching: function hooks
// and memory patches apply immediately at hook time.
// arm64/arm64e only — the static lib has no armv7 slice, so the @interface
// stays visible for the registry but the @implementation is arch-gated and
// dobby_available() reports NO on armv7.
@interface HKDobbyBackend : NSObject <HKSubstitutorBackend> {
    int _lastErrno;
}
@end

#if defined(__arm64__) || defined(__arm64e__)
@implementation HKDobbyBackend
- (BOOL)batchingSupported {
    return NO;
}

- (int)lastErrno {
    return _lastErrno;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    // DobbyHook returns 0 on success; -1 on failure (null address, already
    // hooked, or routing error). Hooks by address — no exported-symbol check.
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

- (HKImageRef)openImage:(NSString *)path {
    // RTLD_NOLOAD: inspect-only, never loads the dylib — matches the MS/ElleKit
    // contract that openImage does not load images
    return (HKImageRef)dlopen([path fileSystemRepresentation], RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD);
}

- (void)closeImage:(HKImageRef)image {
    if(image) {
        dlclose((void *)image);
    }
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    const char *symbol = [symbolName UTF8String];

    if(image) {
        return dlsym((void *)image, symbol);
    }

    // image == NULL: search the default scope, then all loaded dyld images
    void *found = dlsym(RTLD_DEFAULT, symbol);

    if(found) {
        return found;
    }

    return hk_search_loaded_images(^void *(const char *image_name) {
        void *handle = dlopen(image_name, RTLD_LAZY | RTLD_NOLOAD);

        if(!handle) {
            return NULL;
        }

        void *result = dlsym(handle, symbol);
        dlclose(handle);
        return result;
    });
}
@end
#else   // !arm64: stub — the class symbol must exist for the registry entry,
        // but dobby_available() is NO on armv7 so this is never instantiated.
@implementation HKDobbyBackend
- (BOOL)batchingSupported {
    return NO;
}

- (int)lastErrno {
    return _lastErrno;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks {
    return HK_OK;
}

- (HKImageRef)openImage:(NSString *)path {
    return NULL;
}

- (void)closeImage:(HKImageRef)image {
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    return NULL;
}
@end
#endif

#pragma mark - Frida (HKGum) runtime resolution

// Frida hooks through the HKGum.dylib wrapper, dlopen'd at runtime via
// RootBridge (same pattern as libhooker/libsubstitute): the framework never
// links frida-gum directly. No arch guard — everything is runtime dlopen, and
// on armv7 dlopen simply fails (the wrapper product is arch-gated in the
// Makefile). The devkit's minos=14.0 also gates older iOS: dyld refuses to
// dlopen HKGum.dylib on iOS 12/13, so dlopen failure is the whole gate.
static void *hkgum_handle = NULL;
static int (*fn_hkgum_hook_function)(void *, void *, void **) = NULL;
static int (*fn_hkgum_begin_transaction)(void) = NULL;
static int (*fn_hkgum_end_transaction)(void) = NULL;

// Frida backend: inline hooking via frida-gum, loaded at runtime through the
// HKGum.dylib wrapper (vendor/gum/hkgum.c). No ObjC message hooking and no
// memory patching; batching is supported via gum interceptor transactions.
@interface HKFridaBackend : NSObject <HKSubstitutorBackend>
@end

@implementation HKFridaBackend {
    int _lastErrno;
}
- (BOOL)batchingSupported {
    return YES;
}

- (int)lastErrno {
    return _lastErrno;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
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

- (HKImageRef)openImage:(NSString *)path {
    // RTLD_NOLOAD: inspect-only, never loads the dylib — matches the MS/ElleKit
    // contract that openImage does not load images
    return (HKImageRef)dlopen([path fileSystemRepresentation], RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD);
}

- (void)closeImage:(HKImageRef)image {
    if(image) {
        dlclose((void *)image);
    }
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    const char *symbol = [symbolName UTF8String];

    if(image) {
        return dlsym((void *)image, symbol);
    }

    // image == NULL: search the default scope, then all loaded dyld images
    void *found = dlsym(RTLD_DEFAULT, symbol);

    if(found) {
        return found;
    }

    return hk_search_loaded_images(^void *(const char *image_name) {
        void *handle = dlopen(image_name, RTLD_LAZY | RTLD_NOLOAD);

        if(!handle) {
            return NULL;
        }

        void *result = dlsym(handle, symbol);
        dlclose(handle);
        return result;
    });
}
@end

#pragma mark - Backend registry

// One table drives selection, availability, type reporting and the info dicts,
// so adding a backend is a single entry rather than four parallel cascades.
// Order is priority order.
typedef BOOL (*HKBackendAvailability)(void);

typedef struct {
    hookkit_lib_t type;
    __unsafe_unretained Class backendClass;
    __unsafe_unretained NSString *identifier;
    __unsafe_unretained NSString *name;
    HKBackendAvailability available;
    BOOL automatic;     // eligible for +defaultBackend
} HKBackendDescriptor;

// fishhook is compiled in, so it is the floor that is always present.
static BOOL fishhook_available(void) {
    return YES;
}

static BOOL native_available(void) {
    return hk_native_supported() ? YES : NO;
}

// Dobby is compiled in on arm64/arm64e only (the vendored static lib has no
// armv7 slice); the table entry stays on every arch so the count is stable.
static BOOL dobby_available(void) {
#if defined(__arm64__) || defined(__arm64e__)
    return YES;
#else
    return NO;
#endif
}

// Frida is available when the HKGum.dylib wrapper dlopens (see the resolution
// block above). Only successful probes are cached: if dlopen fails, a later
// call retries.
static BOOL frida_available(void) {
    static BOOL cached = NO;
    static BOOL available = NO;

    if(cached) {
        return available;
    }

    hkgum_handle = dlopen([[RootBridge getJBPath:@"/usr/lib/HKGum.dylib"] fileSystemRepresentation], RTLD_LAZY);

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

static const HKBackendDescriptor *hk_backends(size_t *outCount) {
    static HKBackendDescriptor table[7];
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        table[0] = (HKBackendDescriptor){ HK_LIB_ELLEKIT, [HKElleKitBackend class], @"ellekit", @"ElleKit", libhooker_available, YES };
        table[1] = (HKBackendDescriptor){ HK_LIB_SUBSTRATE, [HKSubstrateBackend class], @"substrate", @"Cydia Substrate", substrate_available, YES };
        table[2] = (HKBackendDescriptor){ HK_LIB_SUBSTITUTE, [HKSubstituteBackend class], @"substitute", @"Substitute", substitute_available, YES };
        // Never automatic: HookKit's own engine is opt-in so that devices with
        // a battle-tested library installed keep using it.
        table[3] = (HKBackendDescriptor){ HK_LIB_NATIVE, [HKNativeBackend class], @"native", @"HookKit", native_available, NO };
        table[4] = (HKBackendDescriptor){ HK_LIB_DOBBY, [HKDobbyBackend class], @"dobby", @"Dobby", dobby_available, YES };
        // Never automatic: Frida is opt-in — Dobby is compiled in and lighter;
        // Frida is the premium arm64e-tested engine users request explicitly.
        table[5] = (HKBackendDescriptor){ HK_LIB_FRIDA, [HKFridaBackend class], @"frida", @"Frida", frida_available, NO };
        table[6] = (HKBackendDescriptor){ HK_LIB_FISHHOOK, [HKFishhookBackend class], @"fishhook", @"fishhook", fishhook_available, YES };
    });

    *outCount = sizeof(table) / sizeof(table[0]);
    return table;
}

#pragma mark - HKSubstitutor

@interface HKSubstitutor ()
- (void)noteHookResult:(hookkit_status_t)status;
- (hookkit_lib_t)backendType;
@end

@implementation HKSubstitutor {
    id<HKSubstitutorBackend> backend;
    NSMutableArray<HKHookOperation *> *batchHooks;
    int lastLibErrno;
    hookkit_lib_t lastLibErrnoType;
    // Priority-ordered list of hookkit_lib_t (NSNumber), from substitutorWithOrderedTypes:.
    // Overrides the fixed table priority when set.
    NSArray<NSNumber *> *orderedTypes;
}

@synthesize types, batching, activeType;

+ (id<HKSubstitutorBackend>)defaultBackend {
    size_t count = 0;
    const HKBackendDescriptor *table = hk_backends(&count);

    for(size_t i = 0; i < count; i++) {
        if(table[i].automatic && table[i].available()) {
            return [table[i].backendClass new];
        }
    }

    return nil;
}

- (instancetype)init {
    if((self = [super init])) {
        batchHooks = [NSMutableArray new];
        backend = nil;
        types = HK_LIB_NONE;
        activeType = HK_LIB_NONE;
        lastLibErrno = 0;
        lastLibErrnoType = HK_LIB_NONE;
    }

    return self;
}

- (void)initLibraries {
    if(backend) {
        // idempotent: never re-resolve mid-flight (e.g. engine switching)
        return;
    }

    if(orderedTypes.count) {
        size_t count = 0;
        const HKBackendDescriptor *table = hk_backends(&count);

        types = HK_LIB_NONE;

        for(NSNumber *num in orderedTypes) {
            for(size_t i = 0; i < count; i++) {
                if(table[i].type == (hookkit_lib_t)num.unsignedIntegerValue && table[i].available()) {
                    backend = [table[i].backendClass new];
                    types |= table[i].type;
                    break;
                }
            }

            if(backend) {
                break;
            }
        }
    } else if(types == HK_LIB_NONE) {
        backend = [[self class] defaultBackend];
    } else {
        size_t count = 0;
        const HKBackendDescriptor *table = hk_backends(&count);

        for(size_t i = 0; i < count; i++) {
            if((types & table[i].type) && table[i].available()) {
                backend = [table[i].backendClass new];
                break;
            }
        }
    }
    // explicit types with none available: backend stays nil — the request is
    // honest; the consumer guards with getAvailableSubstitutorTypes

    if(backend) {
        activeType = [self backendType];
    } else {
        activeType = HK_LIB_NONE;
    }
}

- (hookkit_lib_t)backendType {
    size_t count = 0;
    const HKBackendDescriptor *table = hk_backends(&count);

    for(size_t i = 0; i < count; i++) {
        if([backend isKindOfClass:table[i].backendClass]) {
            return table[i].type;
        }
    }

    return HK_LIB_NONE;
}

- (void)noteHookResult:(hookkit_status_t)status {
    if(status == HK_OK || status == HK_ERR_INVALID_ARGUMENT) {
        // success, or a caller error with no backend-specific detail
        lastLibErrno = 0;
        lastLibErrnoType = HK_LIB_NONE;
    } else if(backend) {
        lastLibErrno = [backend lastErrno];
        lastLibErrnoType = activeType;
    } else {
        lastLibErrno = 0;
        lastLibErrnoType = HK_LIB_NONE;
    }
}

+ (hookkit_lib_t)getAvailableSubstitutorTypes {
    hookkit_lib_t types = HK_LIB_NONE;
    size_t count = 0;
    const HKBackendDescriptor *table = hk_backends(&count);

    for(size_t i = 0; i < count; i++) {
        if(table[i].available()) {
            types |= table[i].type;
        }
    }

    return types;
}

+ (NSArray<NSDictionary *> *)getSubstitutorTypeInfo:(hookkit_lib_t)types {
    NSMutableArray *result = [NSMutableArray new];
    size_t count = 0;
    const HKBackendDescriptor *table = hk_backends(&count);

    for(size_t i = 0; i < count; i++) {
        if((types & table[i].type) && table[i].available()) {
            [result addObject:@{
                @"id" : table[i].identifier,
                @"name" : table[i].name,
                @"type" : @(table[i].type)
            }];
        }
    }

    return [result copy];
}

+ (instancetype)substitutorWithTypes:(hookkit_lib_t)types {
    HKSubstitutor *substitutor = [self new];
    [substitutor setTypes:types];
    [substitutor initLibraries];
    return substitutor;
}

+ (instancetype)substitutorWithOrderedTypes:(NSArray<NSNumber *> *)types {
    HKSubstitutor *substitutor = [self new];
    substitutor->orderedTypes = [types copy];
    [substitutor initLibraries];
    return substitutor;
}

+ (instancetype)defaultSubstitutor {
    static HKSubstitutor *defaultSubstitutor = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        defaultSubstitutor = [self new];
        [defaultSubstitutor initLibraries];
    });

    return defaultSubstitutor;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    if(!objcClass || !selector || !replacement) {
        [self noteHookResult:HK_ERR_INVALID_ARGUMENT];
        return HK_ERR_INVALID_ARGUMENT;
    }

    if(!backend) {
        [self noteHookResult:HK_ERR_NOT_SUPPORTED];
        return HK_ERR_NOT_SUPPORTED;
    }

    if(batching && [backend batchingSupported]) {
        HKHookOperation *hook = [HKHookOperation new];
        hook->kind = HKHookKindMessage;
        hook->objcClass = objcClass;
        hook->selector = selector;
        hook->replacement = replacement;
        hook->callerOrig = old_ptr;

        @synchronized(self) {
            [batchHooks addObject:hook];
        }

        [self noteHookResult:HK_OK];
        return HK_OK;
    }

    // owned cell: the backend never touches the caller's pointer directly
    void *cell = NULL;
    hookkit_status_t result = [backend hookMessageInClass:objcClass withSelector:selector withReplacement:replacement outOldPtr:&cell];

    if(result == HK_OK && old_ptr) {
        *old_ptr = cell;
    }

    [self noteHookResult:result];
    return result;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    if(!function || !replacement) {
        [self noteHookResult:HK_ERR_INVALID_ARGUMENT];
        return HK_ERR_INVALID_ARGUMENT;
    }

    if(!backend) {
        [self noteHookResult:HK_ERR_NOT_SUPPORTED];
        return HK_ERR_NOT_SUPPORTED;
    }

    if(batching && [backend batchingSupported]) {
        HKHookOperation *hook = [HKHookOperation new];
        hook->kind = HKHookKindFunction;
        hook->function = function;
        hook->replacement = replacement;
        hook->callerOrig = old_ptr;

        @synchronized(self) {
            [batchHooks addObject:hook];
        }

        [self noteHookResult:HK_OK];
        return HK_OK;
    }

    // owned cell: the backend never touches the caller's pointer directly
    void *cell = NULL;
    hookkit_status_t result = [backend hookFunction:function withReplacement:replacement outOldPtr:&cell];

    if(result == HK_OK && old_ptr) {
        *old_ptr = cell;
    }

    [self noteHookResult:result];
    return result;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    if(!target || !data || size == 0) {
        [self noteHookResult:HK_ERR_INVALID_ARGUMENT];
        return HK_ERR_INVALID_ARGUMENT;
    }

    if(!backend) {
        [self noteHookResult:HK_ERR_NOT_SUPPORTED];
        return HK_ERR_NOT_SUPPORTED;
    }

    if(batching && [backend batchingSupported]) {
        HKHookOperation *hook = [HKHookOperation new];
        hook->kind = HKHookKindMemory;
        hook->target = target;
        // copy the patch bytes now: the caller's buffer must not outlive the call
        hook->data = [NSData dataWithBytes:data length:size];
        hook->size = size;

        @synchronized(self) {
            [batchHooks addObject:hook];
        }

        [self noteHookResult:HK_OK];
        return HK_OK;
    }

    hookkit_status_t result = [backend hookMemory:target withData:data size:size];
    [self noteHookResult:result];
    return result;
}

- (HKImageRef)openImage:(NSString *)path {
    if(!path) {
        return NULL;
    }

    if(!backend) {
        return NULL;
    }

    return [backend openImage:path];
}

- (void)closeImage:(HKImageRef)image {
    if(backend && image) {
        [backend closeImage:image];
    }
}

- (hookkit_status_t)findSymbolsInImage:(HKImageRef)image symbolNames:(NSArray<NSString *> *)symbolNames outSymbols:(NSArray<NSValue *> **)outSymbols {
    if(!symbolNames || ![symbolNames count] || !outSymbols) {
        return HK_ERR_INVALID_ARGUMENT;
    }

    NSMutableArray *outSyms = [NSMutableArray new];
    NSUInteger found = 0;

    for(NSString *symbolName in symbolNames) {
        void *symbol = [self findSymbolInImage:image symbolName:symbolName];

        if(symbol) {
            found += 1;
        }

        [outSyms addObject:[NSValue valueWithPointer:symbol]];
    }

    *outSymbols = [outSyms copy];

    if(found == [symbolNames count]) {
        return HK_OK;
    }

    return found > 0 ? HK_ERR_PARTIAL : HK_ERR;
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    if(!symbolName || ![symbolName length]) {
        return NULL;
    }

    if(!backend) {
        return NULL;
    }

    return [backend findSymbolInImage:image symbolName:symbolName];
}

- (hookkit_status_t)executeHooks {
    NSArray<HKHookOperation *> *hooks;

    @synchronized(self) {
        if(![batchHooks count]) {
            [self noteHookResult:HK_OK];
            return HK_OK;
        }

        hooks = [batchHooks copy];
        [batchHooks removeAllObjects];
    }

    hookkit_status_t result = backend ? [backend executeHooks:hooks] : HK_ERR_NOT_SUPPORTED;

    // copy per-op results back to the callers and drop all borrowed references
    for(HKHookOperation *hook in hooks) {
        if(hook->callerOrig) {
            if(hook->succeeded) {
                *hook->callerOrig = hook->origValue;
            }

            hook->callerOrig = NULL;
        }
    }

    [self noteHookResult:result];
    return result;
}

- (int)getLibErrno:(hookkit_lib_t *)outType {
    if(outType) {
        *outType = lastLibErrnoType;
    }

    return lastLibErrno;
}
@end
