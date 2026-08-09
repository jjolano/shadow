#import "Internal/HKBackendInternal.h"

#import <dlfcn.h>
#import <errno.h>
#import <stdlib.h>
#import <string.h>

#import "vendor/libhooker/libhooker.h"
#import "vendor/libhooker/libblackjack.h"

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
BOOL libhooker_available(void) {
    static BOOL cached = NO;
    static BOOL available = NO;

    if(cached) {
        return available;
    }

    NSString *jbPath = HKJBPath(@"/usr/lib/libhooker.dylib");

    if(!jbPath) {
        return NO;
    }

    libhooker_handle = dlopen([jbPath fileSystemRepresentation], RTLD_LAZY);

    if(!libhooker_handle) {
        return NO;
    }

    // Resolve into locals first: the globals are published only after the
    // ENTIRE required symbol set is present, so an incomplete library can
    // never leave half-populated function pointers behind.
    enum LIBHOOKER_ERR (*LBHookMessage)(Class, SEL, void *, void *) = (enum LIBHOOKER_ERR (*)(Class, SEL, void *, void *))dlsym(libhooker_handle, "LBHookMessage");
    int (*LHHookFunctions)(const struct LHFunctionHook *, int) = (int (*)(const struct LHFunctionHook *, int))dlsym(libhooker_handle, "LHHookFunctions");
    int (*LHPatchMemory)(const struct LHMemoryPatch *, int) = (int (*)(const struct LHMemoryPatch *, int))dlsym(libhooker_handle, "LHPatchMemory");
    struct libhooker_image *(*LHOpenImage)(const char *) = (struct libhooker_image *(*)(const char *))dlsym(libhooker_handle, "LHOpenImage");
    void (*LHCloseImage)(struct libhooker_image *) = (void (*)(struct libhooker_image *))dlsym(libhooker_handle, "LHCloseImage");
    bool (*LHFindSymbols)(struct libhooker_image *, const char **, void **, size_t) = (bool (*)(struct libhooker_image *, const char **, void **, size_t))dlsym(libhooker_handle, "LHFindSymbols");

    // ABI-incomplete: drop the handle and stay uncached so a later probe
    // genuinely retries (the engine may gain the full ABI after HookKit
    // loads). Nothing was published.
    if(!(LBHookMessage && LHHookFunctions && LHPatchMemory
            && LHOpenImage && LHCloseImage && LHFindSymbols)) {
        dlclose(libhooker_handle);
        libhooker_handle = NULL;
        return NO;
    }

    fn_LBHookMessage = LBHookMessage;
    fn_LHHookFunctions = LHHookFunctions;
    fn_LHPatchMemory = LHPatchMemory;
    fn_LHOpenImage = LHOpenImage;
    fn_LHCloseImage = LHCloseImage;
    fn_LHFindSymbols = LHFindSymbols;

    cached = YES;
    available = YES;

    return available;
}

#pragma mark - HKElleKitBackend

@implementation HKElleKitBackend
- (BOOL)batchingSupported {
    return YES;
}

- (BOOL)supportsHookKind:(HKHookKind)kind {
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

    // Clear first: a short count does not necessarily write errno, and the
    // stale thread-local value would otherwise be reported as this call's
    // failure detail.
    errno = 0;
    int result = fn_LHHookFunctions(&hook, 1);
    // LHHookFunctions returns the count of hooks applied; the actual error
    // detail is errno, read immediately after the failing call.
    _lastErrno = result != 1 ? errno : 0;
    return result == 1 ? HK_OK : HK_ERR;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    struct LHMemoryPatch patch = {
        target, data, size, 0
    };

    errno = 0;
    int result = fn_LHPatchMemory(&patch, 1);
    _lastErrno = result != 1 ? errno : 0;
    return result == 1 ? HK_OK : HK_ERR;
}

- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks {
    int total = (int)[hooks count];
    int succeeded = 0;
    // First-failure detail across the whole batch: message ops report the
    // LIBHOOKER_ERR enum, the count-based APIs report errno (cleared just
    // before the call so a short count without an errno write cannot leak a
    // stale thread-local value). Set once, on the FIRST failure; a later
    // success never erases an earlier failure's detail, and a successful
    // memory batch no longer erases an earlier function-batch failure.
    int detail = 0;

    NSMutableData *functionHooks = [NSMutableData new];
    NSMutableData *memoryHooks = [NSMutableData new];
    NSMutableArray<HKHookOperation *> *functionOps = [NSMutableArray new];
    NSMutableArray<HKHookOperation *> *memoryOps = [NSMutableArray new];

    for(HKHookOperation *hook in hooks) {
        switch(hook->kind) {
            case HKHookKindMessage: {
                enum LIBHOOKER_ERR result = fn_LBHookMessage(hook->objcClass, hook->selector, hook->replacement, (void *)&hook->origValue);

                if(result == LIBHOOKER_OK) {
                    hook->succeeded = YES;
                    succeeded += 1;
                } else if(!detail) {
                    detail = result;
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
        errno = 0;
        int result = fn_LHHookFunctions([functionHooks mutableBytes], count);

        if(result < count) {
            // read the detail immediately, before the log below can clobber errno
            int failureErrno = errno;

            if(!detail) {
                detail = failureErrno;
            }

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
        errno = 0;
        int result = fn_LHPatchMemory([memoryHooks mutableBytes], count);

        if(result < count) {
            int failureErrno = errno;

            if(!detail) {
                detail = failureErrno;
            }

            NSLog(@"[HKElleKit] warning: batch LHPatchMemory retval less than expected (%d/%lu)", result, (unsigned long)([memoryHooks length] / sizeof(struct LHMemoryPatch)));
        }

        for(int i = 0; i < result; i++) {
            memoryOps[i]->succeeded = YES;
        }

        succeeded += result;
    }

    _lastErrno = detail;

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