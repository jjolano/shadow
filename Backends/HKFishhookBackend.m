#import "Internal/HKBackendInternal.h"

#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>

#if __has_include(<ptrauth.h>)
#import <ptrauth.h>
#endif

#import "vendor/fishhook/fishhook.h"

#pragma mark - HKFishhookRebinding

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

#pragma mark - HKFishhookBackend

@implementation HKFishhookBackend {
    int _lastErrno;
}
- (BOOL)batchingSupported {
    return NO;
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
    const char *name = info.dli_sname;
    if (name && name[0] == '_') name++;
    owned->name = strdup(name);
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
    _lastErrno = 0;
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks {
    // nothing pending: function hooks and memory patches apply at hook time
    return HK_OK;
}
@end