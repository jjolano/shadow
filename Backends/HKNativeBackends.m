#import "Internal/HKBackendInternal.h"

#import <dlfcn.h>
#import <errno.h>
#import <objc/runtime.h>
#import <pthread.h>

#import "native/hk_arm64.h"
#import "native/hk_native.h"
#import "native/hk_swift.h"

#pragma mark - HKNativeBackend

@implementation HKNativeBackend {
    int _lastErrno;
}

- (BOOL)batchingSupported {
    return YES;
}

- (BOOL)supportsHookKind:(HKHookKind)kind {
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
    // to this class. class_replaceMethod atomically adds it here (for an
    // inherited/absent method) or replaces it (for an owned one) on THIS class
    // only — never touching the superclass — and reports the implementation
    // we would otherwise have inherited. Works for metaclasses too, so class
    // methods hook through the same path.
    class_replaceMethod(objcClass, selector, (IMP)replacement, method_getTypeEncoding(method));

    if(old_ptr) {
        *old_ptr = (void *)inherited;
    }

    return HK_OK;
}

// The native engine patches executable memory without suspending peer
// threads, so code patching must only happen at load time, on the main
// thread, before the target can run elsewhere (same contract as Substitute).
static BOOL hk_native_ensure_main_thread(void) {
#if TARGET_OS_IPHONE
    if(!pthread_main_np()) {
        return NO;
    }
#endif

    return YES;
}

// Engine failures split into capability misses (the target's shape is outside
// what the engine can safely patch — callers may switch technique) and hard
// errors (the patch was attempted and failed).
static hookkit_status_t hk_native_map_engine_failure(int errnoVal) {
    switch(errnoVal) {
        case HK_NATIVE_ERR_UNSUPPORTED:
        case HK_NATIVE_ERR_SHORT_FUNCTION:
        case HK_NATIVE_ERR_RELOCATE:
            return HK_ERR_NOT_SUPPORTED;

        default:
            return HK_ERR;
    }
}

// Side-effect-free capability preflight for auto-cover routing: mirrors the
// no-write rejections the engine would produce (alignment, self-hook,
// short-function, literal-load) plus the main-thread gate, so a router can
// pick this backend without ever invoking a hook that would be refused. All
// checks read only; a reject leaves the target untouched.
- (hookkit_status_t)preflightFunction:(void *)function withReplacement:(void *)replacement {
    if(!hk_native_ensure_main_thread()) {
        _lastErrno = HK_NATIVE_ERR_UNSUPPORTED;
        return HK_ERR_NOT_SUPPORTED;
    }

    void *rawTarget = function;
    void *rawReplacement = replacement;

#if __has_feature(ptrauth_calls)
    // Strip PAC so the raw address is what the engine inspects (arm64e).
    rawTarget = ptrauth_strip(rawTarget, ptrauth_key_asia);
    rawReplacement = ptrauth_strip(rawReplacement, ptrauth_key_asia);
#endif

    if(((uintptr_t)rawTarget & 0x3) != 0 || rawTarget == rawReplacement) {
        _lastErrno = HK_NATIVE_ERR_UNSUPPORTED;
        return HK_ERR_NOT_SUPPORTED;
    }

    // Overwrite window is the branch size (4 or 16 bytes). Only the earliest
    // instructions matter for the short-function/literal checks.
    if(hk_arm64_has_early_terminator(rawTarget, 16) || hk_arm64_has_aarch64_literal_load(rawTarget, 16)) {
        _lastErrno = HK_NATIVE_ERR_SHORT_FUNCTION;
        return HK_ERR_NOT_SUPPORTED;
    }

    return HK_OK;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    if(!hk_native_ensure_main_thread()) {
        _lastErrno = HK_NATIVE_ERR_UNSUPPORTED;
        return HK_ERR_NOT_SUPPORTED;
    }

    void *orig = NULL;

    if(!hk_native_hook_function(function, replacement, &orig)) {
        _lastErrno = hk_native_last_error();
        return hk_native_map_engine_failure(_lastErrno);
    }

    _lastErrno = 0;

    if(old_ptr) {
        *old_ptr = orig;
    }

    return HK_OK;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    if(!hk_native_ensure_main_thread()) {
        _lastErrno = HK_NATIVE_ERR_UNSUPPORTED;
        return HK_ERR_NOT_SUPPORTED;
    }

    if(!hk_native_patch_memory(target, data, size)) {
        _lastErrno = hk_native_last_error();
        return hk_native_map_engine_failure(_lastErrno);
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

#pragma mark - HKSwiftBackend

@implementation HKSwiftBackend {
    int _lastErrno;
}

- (BOOL)batchingSupported {
    return NO;
}

- (BOOL)supportsHookKind:(HKHookKind)kind {
    // Swift vtable hooking is a separate API; none of the three kinds apply
    return NO;
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
    // nothing pending: Swift hooks apply at hook time (batchingSupported NO)
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

// Engine errors fall into two buckets: class-shape problems mean the target
// is outside v1 scope (NOT_SUPPORTED); lookup/signing/write problems are
// hard errors (HK_ERR).
- (hookkit_status_t)mapEngineError:(int)code {
    switch(code) {
        case HK_SWIFT_ERR_UNSUPPORTED:
        case HK_SWIFT_ERR_NOT_SWIFT:
        case HK_SWIFT_ERR_NOT_CLASS_DESCRIPTOR:
        case HK_SWIFT_ERR_NO_VTABLE:
        case HK_SWIFT_ERR_UNSUPPORTED_LAYOUT:
            return HK_ERR_NOT_SUPPORTED;

        case HK_SWIFT_ERR_NOT_FOUND:
        case HK_SWIFT_ERR_AMBIGUOUS:
        case HK_SWIFT_ERR_PAC_MISMATCH:
        case HK_SWIFT_ERR_INVALID_INDEX:
        case HK_SWIFT_ERR_ARG:
        case HK_SWIFT_ERR_WRITE:
            return HK_ERR;
    }

    return HK_ERR;
}

- (hookkit_status_t)hookSwiftMethodInClass:(Class)objcClass withName:(NSString *)name withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    // owned cell: the engine never touches the caller's pointer directly
    void *orig = NULL;

    if(!hk_swift_hook_method(objcClass, [name UTF8String], replacement, &orig)) {
        _lastErrno = hk_swift_last_error();
        return [self mapEngineError:_lastErrno];
    }

    _lastErrno = 0;

    if(old_ptr) {
        *old_ptr = orig;
    }

    return HK_OK;
}

- (hookkit_status_t)hookSwiftVtableSlotInClass:(Class)objcClass withIndex:(NSUInteger)index withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    void *orig = NULL;

    if(!hk_swift_hook_vtable_slot(objcClass, (uint32_t)index, replacement, &orig)) {
        _lastErrno = hk_swift_last_error();
        return [self mapEngineError:_lastErrno];
    }

    _lastErrno = 0;

    if(old_ptr) {
        *old_ptr = orig;
    }

    return HK_OK;
}
@end