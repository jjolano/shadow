#ifndef hookkit_compat_h
#define hookkit_compat_h

#import <Foundation/Foundation.h>

typedef enum {
    HK_OK = 0,
    HK_ERR = (1 << 0),
    HK_ERR_NOT_SUPPORTED = (1 << 1),
    HK_ERR_INVALID_ARGUMENT = (1 << 2),
    HK_ERR_PARTIAL = (1 << 3)
} hookkit_status_t;

typedef enum {
    HK_LIB_NONE = 0,
    HK_LIB_ELLEKIT = (1 << 0),
    HK_LIB_FISHHOOK = (1 << 1),
    HK_LIB_SUBSTRATE = (1 << 2),
    HK_LIB_SUBSTITUTE = (1 << 3),
    HK_LIB_NATIVE = (1 << 4),
    HK_LIB_DOBBY = (1 << 5),
    HK_LIB_FRIDA = (1 << 6),
    HK_LIB_SWIFT = (1 << 7)
} hookkit_lib_t;

typedef const struct HKImage* HKImageRef;

/*
 * Backend capability matrix:
 *
 *                  message    function    memory    batching
 *   ElleKit        yes        yes         yes       yes
 *   Cydia Substrate yes       yes         no        no
 *   Substitute      yes       yes         no        no
 *   native          yes       yes**     yes       yes
 *   Dobby           no        yes***    yes       no
 *   Frida           no        yes****   no        yes
 *   fishhook        no        yes*      no        no
 *   Swift           no        no (new API only) no  no
 *     * exported symbols only, rebinding by symbol name (see fishhook caveat)
 *     ** arm64/arm64e only (see native caveat)
 *     *** arm64/arm64e only; inline patching needs relaxed codesigning (see Dobby caveat)
 *     **** iOS 14+ and arm64/arm64e only; inline patching needs relaxed
 *          codesigning (see Frida caveat)
 *     ***** Swift vtable hooking is a separate API
 *          (hookSwiftMethodInClass:withName:... / ...withIndex:...), not the
 *          message/function columns (see the Swift caveat below)
 *
 * Symbol name convention: names passed to findSymbolInImage:/
 * findSymbolsInImage: are Substrate-style — C symbols carry no leading
 * underscore ("malloc"); C++ mangled names keep their leading underscore.
 * The Substrate/MS and fishhook backends pass names through unchanged;
 * ElleKit accepts both forms.
 *
 * Threading: hook calls are not thread-safe with respect to the batch queue
 * (enqueue and executeHooks must not race). The native Substitute API
 * additionally requires the main thread.
 *
 * Batch storage lifetime: while batching, the caller's old_ptr is only
 * written by executeHooks and is never retained past it.
 *
 * fishhook caveat: symbol-based rebinding only — private/interior addresses
 * are not rebindable, and old_ptr reflects the state at hook time (fishhook
 * retains the rebinding for all future image loads). arm64e PAC is handled:
 * __auth_got slots are resigned with the asia key and slot-address
 * discriminator, and old_ptr is resigned to the plain function-pointer
 * scheme. A hook whose symbol no loaded image references is refused
 * (HK_ERR_NOT_SUPPORTED) instead of silently succeeding. The rebinding list
 * is thread-safe.
 *
 * native caveat: HookKit's own engine, requiring no hooking library to be
 * installed. Never selected automatically — pass HK_LIB_NATIVE to
 * substitutorWithTypes: to opt in. arm64/arm64e only; on armv7 it reports
 * unavailable. Inline patching needs relaxed codesigning, which holds in a
 * tweak-injected process but not in an unmodified one, and function hooks are
 * refused on targets too short to patch without clobbering their neighbour.
 * Hooks must be installed at load time: patching is not atomic and so is not
 * safe against code already running on another thread.
 *
 * Dobby caveat: inline patching needs relaxed codesigning, which holds in a
 * tweak-injected process but not in an unmodified one — same constraint as
 * native. arm64/arm64e only (the vendored static lib has no armv7 slice);
 * on armv7 it reports unavailable. No ObjC message hooking.
 *
 * Frida caveat: hooks through the HKGum.dylib wrapper (frida-gum devkit,
 * LGPL-2.1 with wxWindows exception) dlopen'd at runtime; the framework never
 * links gum directly. The devkit's minos=14.0 means iOS 14+ only — on iOS
 * 12/13 dyld refuses to load the wrapper, so dlopen failure gates it. Opt-in
 * only (HK_LIB_FRIDA); never selected automatically. arm64/arm64e only (no
 * armv7 gum devkit) — on armv7 dlopen fails. Inline patching needs relaxed
 * codesigning, same as native/Dobby. Hooks must be installed at load time:
 * the prologue patch is not atomic and so is not safe against code already
 * running on another thread.
 *
 * Swift caveat: vtable hooking via the Swift backend (HK_LIB_SWIFT, opt-in,
 * never selected automatically). Rewrites the target slot in the class
 * metadata vtable, so it affects Swift callers of the method only. v1 scope:
 * the class's own methods (no inherited methods), non-generic classes, no
 * resilient superclass, no async methods, no class methods, no extensions;
 * @objc dynamic methods are hookable the same way (their Swift callers still
 * dispatch through the vtable). Devirtualization and inlining can silently
 * bypass vtable dispatch, and KVO-swizzled instances are unaffected. The slot
 * write is a single aligned pointer store (≈ atomic) with no code patching,
 * so no relaxed codesigning is required for the write itself. On arm64e the
 * engine validates its signing recipe against the live slot before writing
 * (PAC pre-write self-check): a mismatch fails the hook cleanly instead of
 * corrupting memory. Swift 5 ABI (iOS 12.2+) and arm64/arm64e only. The
 * replacement must be a raw function pointer with the Swift calling
 * convention (self in x20, heap context in x21 on arm64) — an
 * objc_msgSend-convention IMP will misbehave.
 */

@interface HKSubstitutor : NSObject
@property (assign, nonatomic) hookkit_lib_t types;
@property (assign, nonatomic) BOOL batching;

// The backend type actually in use (HK_LIB_NONE if no backend is available).
@property (readonly, nonatomic) hookkit_lib_t activeType;

// Internally loads selected hooking libraries and resolves symbols. Use if setting the types property manually after instance creation.
- (void)initLibraries;

// Returns an integer representing available substitutor types on the system. Use getSubstitutorTypeInfo to receive an array for more details.
+ (hookkit_lib_t)getAvailableSubstitutorTypes;

// Returns an array of dictionaries containing information on given substitutor types, as supported by the running version of HookKit.
+ (NSArray<NSDictionary *> *)getSubstitutorTypeInfo:(hookkit_lib_t)types;

// Creates an instance of HKSubstitutor with given substitutor types.
+ (instancetype)substitutorWithTypes:(hookkit_lib_t)types;

// Creates an instance of HKSubstitutor with the given substitutor types tried
// in the given priority order — the first available entry wins, regardless of
// the built-in table order. Each element is an NSNumber wrapping a
// hookkit_lib_t. Unknown types are skipped; an empty array yields no backend.
+ (instancetype)substitutorWithOrderedTypes:(NSArray<NSNumber *> *)types;

// Creates an instance of HKSubstitutor using the currently loaded substitutor.
+ (instancetype)defaultSubstitutor;

// Hook method for Objective-C runtime methods. Returns HK_OK if successful.
- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;

// Hook method for C functions. Executes immediately if batching property is disabled. Returns HK_OK if successful.
- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;

// Hook method for memory patching. Executes immediately if batching property is disabled. Returns HK_OK if successful.
- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size;

// Hook a Swift class method by name (Swift backend only; HK_ERR_NOT_SUPPORTED
// on any other backend). `name` semantics:
//   - "$s..." or "_$s..."  — exact match against the method's mangled symbol
//     name (dladdr dli_sname; the leading underscore is stripped before
//     comparison)
//   - anything else        — case-sensitive substring match against the
//     demangled name (e.g. "viewDidLoad" matches
//     "MyApp.ViewController.viewDidLoad()")
// The match must be unique: zero matches returns HK_ERR (errno
// HK_SWIFT_ERR_NOT_FOUND), more than one returns HK_ERR (HK_SWIFT_ERR_AMBIGUOUS)
// with every candidate logged — never a silent first match. The replacement
// must be a raw function pointer with the Swift calling convention (self in
// x20, heap context in x21 on arm64) — an objc_msgSend-convention IMP will
// misbehave. On success *old_ptr receives the original implementation as an
// unsigned code pointer (same calling convention). v1 scope: the class's own
// methods only, non-generic classes, no resilient superclass, no async
// methods, no class methods, no extensions; @objc dynamic methods are
// hookable (affects Swift callers only).
- (hookkit_status_t)hookSwiftMethodInClass:(Class)objcClass withName:(NSString *)name withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;

// Hook a Swift class method by vtable slot index (Swift backend only;
// HK_ERR_NOT_SUPPORTED on any other backend). The index is the method's
// declaration order within the class (slot i <-> method descriptor i), which
// is stable per build and survives symbol stripping — use this API for
// stripped binaries, where name lookup cannot work. Out-of-range indexes
// return HK_ERR (HK_SWIFT_ERR_INVALID_INDEX). Replacement contract and v1
// scope are identical to hookSwiftMethodInClass:withName:.
- (hookkit_status_t)hookSwiftVtableSlotInClass:(Class)objcClass withIndex:(NSUInteger)index withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;

// Returns an opaque pointer to an image for use with findSymbol(s)InImage methods, or NULL if unsuccessful.
- (HKImageRef)openImage:(NSString *)path;

// Closes the image handle from openImage.
- (void)closeImage:(HKImageRef)image;

// Locates private symbols within a given image, and outputs results to outSymbols (missing symbols are NULL entries). image == NULL is supported if the hooking library implements MSFindSymbol. Returns HK_OK if all symbols were found, HK_ERR_PARTIAL if some, HK_ERR if none.
- (hookkit_status_t)findSymbolsInImage:(HKImageRef)image symbolNames:(NSArray<NSString *> *)symbolNames outSymbols:(NSArray<NSValue *> **)outSymbols;

// Just like findSymbolsInImage, but for one symbol. Returns the symbol address, or NULL if not found.
- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName;

// If batching property is enabled, performs all hooks made with batching (if supported) prior to this method being called. Returns HK_OK if successful.
- (hookkit_status_t)executeHooks;

// Returns the error number returned by the last hook method call, if available.
- (int)getLibErrno:(hookkit_lib_t *)outType;
@end

// C-style macros for convenience
#ifndef HK_SUBSTITUTOR
#define HK_SUBSTITUTOR [HKSubstitutor defaultSubstitutor]
#endif

#define HKEnableBatching()  [HK_SUBSTITUTOR setBatching:YES]
#define HKDisableBatching() [HK_SUBSTITUTOR setBatching:NO]
#define HKExecuteBatch()    [HK_SUBSTITUTOR executeHooks]

#define HKHookFunction(_symbol, _replace, _result)  [HK_SUBSTITUTOR hookFunction:_symbol withReplacement:_replace outOldPtr:_result]
#define HKHookMemory(_target, _data, _size)         [HK_SUBSTITUTOR hookMemory:_target withData:_data size:_size]
#define HKHookMessage(_class, _sel, _imp, _result)  [HK_SUBSTITUTOR hookMessageInClass:_class withSelector:_sel withReplacement:_imp outOldPtr:(void **)_result]
#define HKHookSwiftMethod(_class, _name, _replace, _result) [HK_SUBSTITUTOR hookSwiftMethodInClass:_class withName:_name withReplacement:_replace outOldPtr:(void **)_result]
#define HKHookSwiftSlot(_class, _index, _replace, _result)  [HK_SUBSTITUTOR hookSwiftVtableSlotInClass:_class withIndex:_index withReplacement:_replace outOldPtr:(void **)_result]

#define HKOpenImage(_path)          (void *)[HK_SUBSTITUTOR openImage:@(_path)]
#define HKCloseImage(_image)        [HK_SUBSTITUTOR closeImage:(HKImageRef)_image]
#define HKFindSymbol(_image, _sym)  [HK_SUBSTITUTOR findSymbolInImage:(HKImageRef)_image symbolName:@(_sym)]
#endif
