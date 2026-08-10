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
// The libhooker ABI is NOT uniform across providers. The vendored header
// (libhooker.h, coolstar's real libhooker for unc0ver/Taurine) declares
// LBHookMessage returning enum LIBHOOKER_ERR and LHHookFunctions/
// LHPatchMemory returning an APPLIED COUNT. ElleKit (Dopamine/palera1n)
// exports the same symbols with a VOID LBHookMessage (success = the out
// pointer being written) and 0-on-success for the other two. Reading one
// provider's return under the other's semantics makes every hook look
// failed, the caller's original IMP gets suppressed, and v1-era tweaks
// whose %orig reads that slot crash with a NULL call (Shadow 3.7.6's
// %hook SpringBoard -applicationDidFinishLaunching: sent SpringBoard into
// safe mode exactly this way).
//
// Detect the provider at probe time via dladdr on the resolved symbol:
// the image name distinguishes ElleKit ("libellekit") from real libhooker.
// Default to ElleKit semantics when detection fails (the modern jailbreak
// default; the header matches neither provider, so it is no fallback).
static BOOL libhooker_uses_applied_count = NO;
static void (*fn_LBHookMessage)(Class, SEL, void *, void *) = NULL;
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
    void (*LBHookMessage)(Class, SEL, void *, void *) = (void (*)(Class, SEL, void *, void *))dlsym(libhooker_handle, "LBHookMessage");
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

    // Provider ABI detection: real libhooker (unc0ver/Taurine) returns an
    // applied count from LHHookFunctions/LHPatchMemory and an errno enum
    // from LBHookMessage; ElleKit returns void/0-on-success. Distinguish by
    // the image the LBHookMessage symbol lives in. dladdr can fail only if
    // the symbol isn't in a loaded image — it is, we just dlsym'd it, so a
    // miss falls through to the ElleKit default.
    Dl_info info;

    if(dladdr((void *)LBHookMessage, &info) && info.dli_fname) {
        libhooker_uses_applied_count = (strstr(info.dli_fname, "libellekit") == NULL);
    }

    cached = YES;
    available = YES;

    return available;
}

// Preflight-only discovery, for the availability-introspection entry points
// (getAvailableSubstitutorTypes / getAvailableCategories): reports loadability
// WITHOUT loading — dlopen_preflight never maps the image and never runs its
// constructors, so introspection cannot initialize a hooking provider.
// Deliberately uncached: the check is a single stat-family syscall on the
// preflight path, and an uncached probe retries if the engine appears after
// HookKit loads (mirroring the activation probe's retry contract).
BOOL libhooker_discoverable(void) {
    NSString *jbPath = HKJBPath(@"/usr/lib/libhooker.dylib");

    if(!jbPath) {
        return NO;
    }

    return dlopen_preflight([jbPath fileSystemRepresentation]);
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
    // LBHookMessage's ABI is provider-dependent:
    //  - ElleKit: void — success is the original being written into the out
    //    cell; nothing written means the selector exists on neither the class
    //    nor the metaclass (ElleKit messageHook's guard).
    //  - real libhooker: int — LIBHOOKER_OK (0) on success,
    //    LIBHOOKER_ERR_SELECTOR_NOT_FOUND (1) when the selector is absent.
    // Both write the original on success, so the out cell is the common
    // success signal; check it before any return-value reading. Reading the
    // void return as an error enum was the ABI mismatch: the garbage value
    // (typically the original's low bits) was treated as failure, the
    // caller's original stayed suppressed, and v1-era tweaks calling %orig
    // through the NULL slot crashed (Shadow 3.7.6's %hook SpringBoard was
    // exactly this).
    void *cell = NULL;
    fn_LBHookMessage(objcClass, selector, replacement, (void *)&cell);

    if(!cell) {
        _lastErrno = LIBHOOKER_ERR_SELECTOR_NOT_FOUND;
        return HK_ERR_NOT_SUPPORTED;
    }

    _lastErrno = 0;

    if(old_ptr) {
        *old_ptr = cell;
    }

    return HK_OK;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    struct LHFunctionHook hook = {
        function, replacement, (void *)old_ptr, NULL
    };

    // LHHookFunctions semantics by provider:
    //  - ElleKit: LIBHOOKER_OK (0) on success; non-zero is the failure detail.
    //  - real libhooker: applied count (1 for a single hook); 0 on failure.
    // A single-hook call succeeds when the result equals the requested count
    // under the applied-count ABI, or equals LIBHOOKER_OK under ElleKit's.
    _lastErrno = 0;
    int result = fn_LHHookFunctions(&hook, 1);

    if(libhooker_uses_applied_count) {
        _lastErrno = result == 1 ? 0 : result;
        return result == 1 ? HK_OK : HK_ERR;
    }

    _lastErrno = result;
    return result == LIBHOOKER_OK ? HK_OK : HK_ERR;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    struct LHMemoryPatch patch = {
        target, data, size, 0
    };

    // LHPatchMemory semantics by provider:
    //  - ElleKit: LIBHOOKER_OK (0) on success, 1 when a patch is malformed.
    //  - real libhooker: applied count (1 for a single patch); 0 on failure.
    _lastErrno = 0;
    int result = fn_LHPatchMemory(&patch, 1);

    if(libhooker_uses_applied_count) {
        _lastErrno = result == 1 ? 0 : result;
        return result == 1 ? HK_OK : HK_ERR;
    }

    _lastErrno = result;
    return result == LIBHOOKER_OK ? HK_OK : HK_ERR;
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
                // void LBHookMessage: success is the original being written
                // into hook->origValue; there is no status return to read.
                hook->origValue = NULL;
                fn_LBHookMessage(hook->objcClass, hook->selector, hook->replacement, (void *)&hook->origValue);

                if(hook->origValue) {
                    hook->succeeded = YES;
                    succeeded += 1;
                } else if(!detail) {
                    detail = LIBHOOKER_ERR_SELECTOR_NOT_FOUND;
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

        if(libhooker_uses_applied_count) {
            // Real libhooker: result is the number of hooks applied. ElleKit
            // semantics can't be assumed here — a successful batch returns
            // the full count, so treat result == count as all-succeeded.
            if(result < count) {
                if(!detail) {
                    detail = result;
                }

                NSLog(@"[HKElleKit] warning: batch LHHookFunctions retval less than expected (%d/%d)", result, count);
            }

            for(int i = 0; i < result; i++) {
                functionOps[i]->succeeded = YES;
            }

            succeeded += result;
        } else {
            // ElleKit: LIBHOOKER_OK (0) on success; non-zero is the failure
            // detail itself, not a partial count. A 0 return means every op
            // succeeded (ElleKit iterates all entries and writes each orig).
            if(result != LIBHOOKER_OK) {
                if(!detail) {
                    detail = result;
                }

                NSLog(@"[HKElleKit] warning: batch LHHookFunctions failed (%d)", result);
            } else {
                for(HKHookOperation *op in functionOps) {
                    op->succeeded = YES;
                }

                succeeded += count;
            }
        }
    }

    if([memoryHooks length]) {
        int count = (int)([memoryHooks length] / sizeof(struct LHMemoryPatch));
        errno = 0;
        int result = fn_LHPatchMemory([memoryHooks mutableBytes], count);

        if(libhooker_uses_applied_count) {
            if(result < count) {
                if(!detail) {
                    detail = result;
                }

                NSLog(@"[HKElleKit] warning: batch LHPatchMemory retval less than expected (%d/%d)", result, count);
            }

            for(int i = 0; i < result; i++) {
                memoryOps[i]->succeeded = YES;
            }

            succeeded += result;
        } else {
            if(result != LIBHOOKER_OK) {
                if(!detail) {
                    detail = result;
                }

                NSLog(@"[HKElleKit] warning: batch LHPatchMemory failed (%d)", result);
            } else {
                for(HKHookOperation *op in memoryOps) {
                    op->succeeded = YES;
                }

                succeeded += count;
            }
        }
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