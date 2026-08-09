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
    HK_LIB_SWIFT = (1 << 7),
    HK_LIB_LITEHOOK = (1 << 8)
} hookkit_lib_t;

typedef const struct HKImage* HKImageRef;

/*
 * Backend category flags. Categories group backends by hooking capability;
 * callers use substitutorWithCategory: to select the first available backend
 * in that category's priority order, without naming a specific library.
 *
 *   MESSAGE          — ObjC message hooking (class_addMethod / MSHookMessageEx /
 *                      LBHookMessage / substitute_hook_objc_message)
 *   FUNCTION_REBIND  — C function rebinding by exported symbol name (fishhook)
 *   FUNCTION_INLINE  — C function inline hooking by address (Dobby / Frida /
 *                      ElleKit LHHookFunctions)
 *   PRIVATE_SYMBOL   — Private symbol lookup in a loaded image (ElleKit /
 *                      Substrate / Substitute)
 *
 * Flags are powers of two and may be OR'd for getAvailableCategories.
 */
typedef enum {
    HK_CAT_NONE             = 0,
    HK_CAT_MESSAGE          = (1 << 0),
    HK_CAT_FUNCTION_REBIND  = (1 << 1),
    HK_CAT_FUNCTION_INLINE  = (1 << 2),
    HK_CAT_PRIVATE_SYMBOL   = (1 << 3)
} hookkit_cat_t;

/*
 * Backend capability matrix:
 *
 *                  message    function    memory    batching
 *   ElleKit        yes        yes         yes       yes
 *   Cydia Substrate yes       yes         yes*9     no
 *   Substitute      yes       yes         yes*10    no
 *   native          yes       yes**     yes       yes
 *   Dobby           no        yes***    yes       no
 *   Frida           no        yes****   no        yes
 *   fishhook        no        yes*      no        no
 *   Swift           no        no*****   no        no
 *   litehook        no        yes*8     yes       no
 *     * exported symbols only, rebinding by symbol name
 *     ** arm64/arm64e only
 *     *** arm64/arm64e only; inline patching needs relaxed codesigning
 *     **** iOS 14+ and arm64/arm64e only; inline patching needs relaxed
 *          codesigning
 *     ***** Swift vtable hooking is a separate API
 *          (hookSwiftMethodInClass:withName:... / ...withIndex:...), not the
 *          message/function columns
 *     *8  exported-symbol/address rebinding via litehook_rebind_symbol; no
 *         original-call trampoline for direct-branch hooks
 *     *9  via MSHookMemory when the installed Cydia Substrate exports it
 *     *10 via the MS-compatible SubHookMemory on Substitute
 *   Each footnote is expanded in the per-backend caveats linked below.
 *
 * Symbol name convention: names passed to findSymbolInImage:/
 * findSymbolsInImage: are Substrate-style — C symbols carry no leading
 * underscore ("malloc"); C++ mangled names keep their leading underscore.
 * The Substrate/MS and fishhook backends pass names through unchanged;
 * ElleKit accepts both forms.
 *
 * Threading: the batch queue is thread-safe — enqueue may race executeHooks,
 * which drains a snapshot under the same lock, so every queued hook runs
 * exactly once. Not synchronized: last-error state (getLibErrno: reports the
 * last hook call on that substitutor, from whichever thread made it) and
 * backend selection — settle types / initLibraries before hooking starts. The
 * native Substitute API additionally requires the main thread.
 *
 * Batch storage lifetime: while batching, the caller's old_ptr is only
 * written by executeHooks and is never retained past it.
 *
 * Per-backend caveats — fishhook symbol-only rebinding; native/Dobby/Frida
 * codesigning, arch and load-time constraints; Swift vtable scope and calling
 * convention — live in the "Semantics" section of README.md, which is the
 * canonical copy:
 * https://github.com/jjolano/HookKit#semantics
 */

@interface HKSubstitutor : NSObject
@property (assign, nonatomic) hookkit_lib_t types;
@property (assign, nonatomic) BOOL batching;

// The backend type actually in use (HK_LIB_NONE if no backend is available).
@property (readonly, nonatomic) hookkit_lib_t activeType;

// Resolves the backend from the types property. One-shot: the first call that
// finds a backend wins and later calls are no-ops, so set types before calling.
// The substitutorWith... constructors already do this for you.
- (void)initLibraries;

// Returns an integer representing available substitutor types on the system. Use getSubstitutorTypeInfo to receive an array for more details.
+ (hookkit_lib_t)getAvailableSubstitutorTypes;

// Returns the OR of all category flags for which at least one backend is
// available on the current device. Callers can use this to probe which
// categories are usable before requesting a backend by category.
+ (hookkit_cat_t)getAvailableCategories;

// Returns an array of dictionaries containing information on given substitutor types, as supported by the running version of HookKit.
+ (NSArray<NSDictionary *> *)getSubstitutorTypeInfo:(hookkit_lib_t)types;

// Creates an instance of HKSubstitutor with given substitutor types.
+ (instancetype)substitutorWithTypes:(hookkit_lib_t)types;

// Creates an instance of HKSubstitutor with the given substitutor types tried
// in the given priority order — the first available entry wins, regardless of
// the built-in table order. Each element is an NSNumber wrapping a
// hookkit_lib_t. Unknown types are skipped; an empty array yields no backend.
+ (instancetype)substitutorWithOrderedTypes:(NSArray<NSNumber *> *)types;

// Creates an instance of HKSubstitutor for the given backend category. The
// first available backend in that category's built-in priority order is
// selected — callers request a capability, not a specific library. Returns
// an instance with no backend (activeType == HK_LIB_NONE) if no backend in
// the category is available. HK_CAT_NONE is equivalent to defaultSubstitutor.
+ (instancetype)substitutorWithCategory:(hookkit_cat_t)category;

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
