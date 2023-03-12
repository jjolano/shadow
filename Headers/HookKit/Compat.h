#ifndef hookkit_compat_h
#define hookkit_compat_h

#import <Foundation/Foundation.h>

typedef enum {
    HK_OK = 0,
    HK_ERR = (1 << 0),
    HK_ERR_NOT_SUPPORTED = (1 << 1)
} hookkit_status_t;

typedef enum {
    HK_LIB_NONE = 0
} hookkit_lib_t;

typedef const struct HKImage* HKImageRef;

@interface HKSubstitutor : NSObject
@property (assign, nonatomic) hookkit_lib_t types;
@property (assign, nonatomic) BOOL batching;

// Internally loads selected hooking libraries and resolves symbols. Use if setting the types property manually after instance creation.
- (void)initLibraries;

// Returns an integer representing available substitutor types on the system. Use getSubstitutorTypeInfo to receive an array for more details.
+ (hookkit_lib_t)getAvailableSubstitutorTypes;

// Returns an array of dictionaries containing information on given substitutor types, as supported by the running version of HookKit.
+ (NSArray<NSDictionary *> *)getSubstitutorTypeInfo:(hookkit_lib_t)types;

// Creates an instance of HKSubstitutor with given substitutor types.
+ (instancetype)substitutorWithTypes:(hookkit_lib_t)types;

// Creates an instance of HKSubstitutor using the currently loaded substitutor.
+ (instancetype)defaultSubstitutor;

// Hook method for Objective-C runtime methods. Returns HK_OK if successful.
- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;

// Hook method for C functions. Executes immediately if batching property is disabled. Returns HK_OK if successful.
- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;

// Hook method for memory patching. Executes immediately if batching property is disabled. Returns HK_OK if successful.
- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size;

// Returns an opaque pointer to an image for use with findSymbol(s)InImage methods, or NULL if unsuccessful.
- (HKImageRef)openImage:(NSString *)path;

// Closes the image handle from openImage.
- (void)closeImage:(HKImageRef)image;

// Locates private symbols within a given image, and outputs results to outSymbols. image == NULL is supported if the hooking library implements MSFindSymbol. Returns HK_OK if successful.
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

#define HKOpenImage(_path)          (void *)[HK_SUBSTITUTOR openImage:@(_path)]
#define HKCloseImage(_image)        [HK_SUBSTITUTOR closeImage:(HKImageRef)_image]
#define HKFindSymbol(_image, _sym)  [HK_SUBSTITUTOR findSymbolInImage:(HKImageRef)_image symbolName:@(_sym)]
#endif
