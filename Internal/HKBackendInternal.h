// HookKit private header: shared declarations for the facade/registry split.
// Lives under Internal/ at the project root and is #imported only by the
// framework's own .m files — it is NOT under Headers/, so it is never
// installed into the public Headers/ tree (the public list is the fixed
// HookKit_PUBLIC_HEADERS set).
#ifndef hookkit_backend_internal_h
#define hookkit_backend_internal_h

#import <HookKit/Compat.h>

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

#pragma mark - Backend protocol

// HKStrategy is public API now (Compat.h, next to hookkit_cat_t) so that
// activeStrategy is observable; the protocol's setStrategy: below is the
// backend-facing channel that consumes it.
@protocol HKSubstitutorBackend <NSObject>
@property (nonatomic, readonly) BOOL batchingSupported;
@property (nonatomic, readonly) int lastErrno;

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;
- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;
- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size;
- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks;
- (BOOL)supportsHookKind:(HKHookKind)kind;

- (HKImageRef)openImage:(NSString *)path;
- (void)closeImage:(HKImageRef)image;
- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName;

// Swift vtable hooking. Optional: only the Swift backend implements these,
// so every other backend inherits HK_ERR_NOT_SUPPORTED through the forwarder.
@optional
- (hookkit_status_t)hookSwiftMethodInClass:(Class)objcClass withName:(NSString *)name withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;
- (hookkit_status_t)hookSwiftVtableSlotInClass:(Class)objcClass withIndex:(NSUInteger)index withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;
// Technique hint for strategy-aware backends (HKLitehookBackend). Optional:
// backends without it keep their vendor default technique.
- (void)setStrategy:(HKStrategy)strategy;
@end

#pragma mark - Backend classes

// ElleKit backend: libhooker API, resolved at runtime via dlopen/dlsym.
@interface HKElleKitBackend : NSObject <HKSubstitutorBackend> {
    int _lastErrno;
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

// Cydia Substrate backend: unc0ver and 32-bit jailbreaks.
@interface HKSubstrateBackend : HKMSBackend
@end

// Substitute backend: checkra1n-classic (Substitute-based jailbreaks).
// Uses libsubstitute's native API when available, otherwise the MS-compatible
// path (which also fixes the leak of Substitute image handles).
@interface HKSubstituteBackend : HKMSBackend
@end

// Shared dlfcn image lookup for the backends whose engines bring no image API
// of their own (fishhook, Dobby, Frida) — the three had byte-identical copies.
// Deliberately not <HKSubstitutorBackend>-conforming: that would warn on the
// six hooking methods it has no business implementing. Subclasses declare the
// protocol themselves.
// ponytail: the native backend has this same shape over hk_native_open_image/
// _find_symbol/_close_image; parameterising open/find/close as ivars to absorb
// it costs more lines than the copy does. Revisit if a fifth copy appears.
// Declared here, not just defined below: -Wprotocol resolves a subclass's
// conformance against declared methods, so the inherited trio must be visible
// at the subclass @interface.
@interface HKDlfcnBackend : NSObject
- (HKImageRef)openImage:(NSString *)path;
- (void)closeImage:(HKImageRef)image;
- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName;
@end

// fishhook backend: rebind_symbols for C functions; dlsym/dyld iteration for symbol lookup.
// Batching is not supported: function hooks are applied immediately, and ObjC message
// hooks and memory patches are not supported at all.
@interface HKFishhookBackend : HKDlfcnBackend <HKSubstitutorBackend>
@end

// litehook backend: strategy-aware — GOT/import rebinding via
// litehook_rebind_symbol (address-based, no symbol-name requirement) by
// default, plus memory patching via litehook_hook_memory. With setStrategy:
// the same backend also serves prologue inline trampolines (litehook_hook_function)
// and DSC private-symbol lookups (litehook_find_dsc_symbol), so one vendor
// covers several categories. Compiled in on all archs; no ObjC message
// hooking, no batching.
// ponytail: litehook_rebind_symbol's kern_return_t carries the failure
// detail (KERN_MEMORY_FAILURE leaves the live rebind list untouched), and the
// zero-match honesty signal comes from its out-param match count, captured
// under the same lock as the apply; hookFunction reports HK_ERR when it is 0.
@interface HKLitehookBackend : HKDlfcnBackend <HKSubstitutorBackend> {
    int _lastErrno;
    // zero-init (HKStrategyDefault): a bare [[self class] new] keeps the
    // vendor default until setStrategy: is called
    HKStrategy _strategy;
}
@end

// Native backend: HookKit's own engine, requiring no hooking library on the
// device. Never selected automatically — callers opt in with HK_LIB_NATIVE.
// See native/hk_native.h for the constraints.
@interface HKNativeBackend : NSObject <HKSubstitutorBackend>
@end

// Swift backend: rewrites Swift class metadata vtable slots via HookKit's own
// engine (native/hk_swift.c). No arch gate — availability is runtime
// (hk_swift_supported() + the Swift 5 runtime check in swift_available()).
// Hooks the class's own methods only, by name or by declaration-order index;
// see native/hk_swift.h for the ABI contract and v1 scope.
@interface HKSwiftBackend : NSObject <HKSubstitutorBackend>
@end

// Dobby backend: inline hooking via the vendored Dobby static library
// (vendor/dobby). Hooks by address, so interior/private C functions work
// (unlike fishhook). No ObjC message hooking and no batching: function hooks
// and memory patches apply immediately at hook time.
// arm64/arm64e only — the static lib has no armv7 slice, so the @interface
// stays visible for the registry but the @implementation is arch-gated and
// dobby_available() reports NO on armv7.
@interface HKDobbyBackend : HKDlfcnBackend <HKSubstitutorBackend> {
    int _lastErrno;
}
@end

// Frida backend: inline hooking via frida-gum, loaded at runtime through the
// HKGum.dylib wrapper (vendor/gum/hkgum.c). No ObjC message hooking and no
// memory patching; batching is supported via gum interceptor transactions.
@interface HKFridaBackend : HKDlfcnBackend <HKSubstitutorBackend>
@end

#pragma mark - Shared helpers

// Jailbreak-root path (RootBridge /var/jb, or libroothide's jbroot on
// roothide). Defined in Backends/HKBackendCommon.m.
NSString *HKJBPath(NSString *path);

// Iterates the loaded dyld images, calling probe with each image's name until
// it returns non-NULL; NULL when no image matched. Defined in
// Backends/HKBackendCommon.m.
void *hk_search_loaded_images(void *(^probe)(const char *imageName));

// Batch honesty helper: HK_OK when every op succeeded, HK_ERR_PARTIAL when
// some did, HK_ERR when none did. Defined in Backends/HKBackendCommon.m.
hookkit_status_t hk_batch_status(int succeeded, int total);

#pragma mark - Backend availability

// The registry's table entries reference these; each is defined next to the
// dlopen/dlsym resolution it drives, in the backend file for that library:
//   libhooker_available   -> Backends/HKElleKitBackend.m
//   substrate_available   -> Backends/HKMSBackends.m
//   substitute_available  -> Backends/HKMSBackends.m
//   frida_available       -> Backends/HKInlineBackends.m
// (fishhook/litehook/native/dobby/swift predicates are compile-time or
// engine checks with no resolver of their own — they stay in the registry).
BOOL libhooker_available(void);
BOOL substrate_available(void);
BOOL substitute_available(void);
BOOL frida_available(void);

#pragma mark - Registry interface

// Backend table + category pickers, owned by HKBackendRegistry.m; the facade
// consumes them for selection, availability reporting and the info dicts.
typedef BOOL (*HKBackendAvailability)(void);

typedef struct {
    hookkit_lib_t type;
    __unsafe_unretained Class backendClass;
    __unsafe_unretained NSString *identifier;
    __unsafe_unretained NSString *name;
    HKBackendAvailability available;
    BOOL automatic;     // eligible for +defaultBackend
    BOOL selectable;    // appears in consumer settings-style pickers
    // no categories field: membership lives in hk_category_priorities only,
    // so the two can never diverge (see getAvailableCategories)
} HKBackendDescriptor;

typedef struct {
    hookkit_lib_t type;
    HKStrategy strategy;
} HKCategoryPicker;

typedef struct {
    hookkit_cat_t category;
    HKCategoryPicker order[8];
    size_t count;
} HKCategoryPriority;

extern const HKCategoryPriority hk_category_priorities[];
extern const size_t hk_category_priority_count;

const HKBackendDescriptor *hk_backends(size_t *outCount);

#endif