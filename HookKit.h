#import <Foundation/Foundation.h>

typedef enum {
    HK_OK = 0,
    HK_ERR = (1 << 0),
    HK_ERR_NOT_SUPPORTED = (1 << 1),
    HK_ERR_SHORT_FUNC = (1 << 2),
    HK_ERR_BAD_INSN_AT_START = (1 << 3),
    HK_ERR_SEL_NOT_FOUND = (1 << 4),
    HK_ERR_VM = (1 << 5)
} hookkit_status_t;

typedef enum {
    HK_LIB_NONE = 0,
    HK_LIB_SUBSTRATE = (1 << 0),
    HK_LIB_SUBSTITUTE = (1 << 1),
    HK_LIB_LIBHOOKER = (1 << 2),
    HK_LIB_LIBBLACKJACK = (1 << 3),
    HK_LIB_FISHHOOK = (1 << 4)
} hookkit_lib_t;

typedef const struct HKImage* HKImageRef;

@interface HookKit : NSObject
@property hookkit_lib_t types;

+ (hookkit_lib_t)getAvailableSubstitutorTypes;
+ (instancetype)substitutorWithTypes:(hookkit_lib_t)types;
+ (instancetype)defaultSubstitutor;

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;
- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;
- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size;

- (HKImageRef)openImage:(NSString *)path;
- (void)closeImage:(HKImageRef)image;

- (hookkit_status_t)findSymbolsInImage:(HKImageRef)image symbolNames:(NSArray<NSString *> *)symbolNames outSymbols:(NSArray<NSNumber *> **)outSymbols;
- (hookkit_status_t)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName outSymbol:(void **)outSymbol;
@end

@interface HKBatchHook : NSObject
- (void)addFunctionHook:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;
- (void)addMemoryHook:(void *)target withData:(const void *)data size:(size_t)size;

- (hookkit_status_t)performHooksWithSubstitutor:(HookKit *)substitutor;
@end
