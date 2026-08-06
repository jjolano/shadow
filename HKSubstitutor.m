#import <HookKit/Compat.h>
#import <RootBridge.h>

#import <dlfcn.h>
#import <mach-o/dyld.h>

#import "vendor/libhooker/libhooker.h"
#import "vendor/libhooker/libblackjack.h"
#import "vendor/fishhook/fishhook.h"

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

static BOOL libhooker_available(void) {
    static BOOL available = NO;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        libhooker_handle = dlopen([[RootBridge getJBPath:@"/usr/lib/libhooker.dylib"] fileSystemRepresentation], RTLD_LAZY);

        if(!libhooker_handle) {
            return;
        }

        fn_LBHookMessage = (enum LIBHOOKER_ERR (*)(Class, SEL, void *, void *))dlsym(libhooker_handle, "LBHookMessage");
        fn_LHHookFunctions = (int (*)(const struct LHFunctionHook *, int))dlsym(libhooker_handle, "LHHookFunctions");
        fn_LHPatchMemory = (int (*)(const struct LHMemoryPatch *, int))dlsym(libhooker_handle, "LHPatchMemory");
        fn_LHOpenImage = (struct libhooker_image *(*)(const char *))dlsym(libhooker_handle, "LHOpenImage");
        fn_LHCloseImage = (void (*)(struct libhooker_image *))dlsym(libhooker_handle, "LHCloseImage");
        fn_LHFindSymbols = (bool (*)(struct libhooker_image *, const char **, void **, size_t))dlsym(libhooker_handle, "LHFindSymbols");

        available = fn_LBHookMessage && fn_LHHookFunctions && fn_LHPatchMemory
            && fn_LHOpenImage && fn_LHCloseImage && fn_LHFindSymbols;
    });

    return available;
}

#pragma mark - Hook operations

typedef NS_ENUM(int, HKHookKind) {
    HKHookKindMessage,
    HKHookKindFunction,
    HKHookKindMemory
};

@interface HKHookOperation : NSObject
@property (assign, nonatomic) HKHookKind kind;
@property (assign, nonatomic) Class objcClass;
@property (assign, nonatomic) SEL selector;
@property (assign, nonatomic) void *function;
@property (assign, nonatomic) void *replacement;
@property (assign, nonatomic) void **orig;
@property (assign, nonatomic) void *target;
@property (assign, nonatomic) const void *data;
@property (assign, nonatomic) size_t size;
@end

@implementation HKHookOperation
@end

#pragma mark - Backends

@protocol HKSubstitutorBackend <NSObject>
@property (nonatomic, readonly) BOOL batchingSupported;

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;
- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr;
- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size;
- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks;

- (HKImageRef)openImage:(NSString *)path;
- (void)closeImage:(HKImageRef)image;
- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName;
@end

// ElleKit backend: libhooker API, resolved at runtime via dlopen/dlsym.
@interface HKElleKitBackend : NSObject <HKSubstitutorBackend>
@end

@implementation HKElleKitBackend
- (BOOL)batchingSupported {
    return YES;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    return fn_LBHookMessage(objcClass, selector, replacement, (void *)old_ptr) == LIBHOOKER_OK ? HK_OK : HK_ERR;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    struct LHFunctionHook hook = {
        function, replacement, (void *)old_ptr, NULL
    };

    return fn_LHHookFunctions(&hook, 1) == 1 ? HK_OK : HK_ERR;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    struct LHMemoryPatch patch = {
        target, data, size, 0
    };

    return fn_LHPatchMemory(&patch, 1) == 1 ? HK_OK : HK_ERR;
}

- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks {
    int total = (int)[hooks count];
    int succeeded = 0;

    NSMutableData *functionHooks = [NSMutableData new];
    NSMutableData *memoryHooks = [NSMutableData new];

    for(HKHookOperation *hook in hooks) {
        switch([hook kind]) {
            case HKHookKindMessage: {
                if(fn_LBHookMessage([hook objcClass], [hook selector], [hook replacement], (void *)[hook orig]) == LIBHOOKER_OK) {
                    succeeded += 1;
                }

                break;
            }

            case HKHookKindFunction: {
                struct LHFunctionHook lh = {
                    [hook function], [hook replacement], (void *)[hook orig], NULL
                };

                [functionHooks appendBytes:&lh length:sizeof(struct LHFunctionHook)];
                break;
            }

            case HKHookKindMemory: {
                struct LHMemoryPatch lh = {
                    [hook target], [hook data], [hook size], 0
                };

                [memoryHooks appendBytes:&lh length:sizeof(struct LHMemoryPatch)];
                break;
            }
        }
    }

    if([functionHooks length]) {
        int result = fn_LHHookFunctions([functionHooks mutableBytes], (int)([functionHooks length] / sizeof(struct LHFunctionHook)));

        if(result < (int)([functionHooks length] / sizeof(struct LHFunctionHook))) {
            NSLog(@"[HKElleKit] warning: batch LHHookFunctions retval less than expected (%d/%lu)", result, (unsigned long)([functionHooks length] / sizeof(struct LHFunctionHook)));
        }

        succeeded += result;
    }

    if([memoryHooks length]) {
        int result = fn_LHPatchMemory([memoryHooks mutableBytes], (int)([memoryHooks length] / sizeof(struct LHMemoryPatch)));

        if(result < (int)([memoryHooks length] / sizeof(struct LHMemoryPatch))) {
            NSLog(@"[HKElleKit] warning: batch LHPatchMemory retval less than expected (%d/%lu)", result, (unsigned long)([memoryHooks length] / sizeof(struct LHMemoryPatch)));
        }

        succeeded += result;
    }

    if(succeeded < total) {
        NSLog(@"[HookKit] warning: successfully hooked less than expected (%d/%lu)", succeeded, (unsigned long)total);
    }

    return succeeded > 0 ? HK_OK : HK_ERR;
}

- (HKImageRef)openImage:(NSString *)path {
    return (HKImageRef)fn_LHOpenImage([path fileSystemRepresentation]);
}

- (void)closeImage:(HKImageRef)image {
    if(image) {
        fn_LHCloseImage((struct libhooker_image *)image);
    }
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    const char *symbol = [symbolName UTF8String];
    void *result = NULL;

    if(image) {
        if(fn_LHFindSymbols((struct libhooker_image *)image, &symbol, &result, 1)) {
            return result;
        }

        return NULL;
    }

    // image == NULL: iterate all loaded dyld images
    int count = _dyld_image_count();

    for(int i = 0; i < count; i++) {
        const char *image_name = _dyld_get_image_name(i);

        if(image_name) {
            struct libhooker_image *libhookerImage = fn_LHOpenImage(image_name);

            if(fn_LHFindSymbols(libhookerImage, &symbol, &result, 1)) {
                fn_LHCloseImage(libhookerImage);

                if(result) {
                    NSLog(@"[HookKit] found symbol %s in image %s", symbol, image_name);
                    return result;
                }
            } else {
                fn_LHCloseImage(libhookerImage);
            }
        }
    }

    return NULL;
}
@end

// fishhook backend: rebind_symbols for C functions; dlsym/dyld iteration for symbol lookup.
// Batching is not supported: function hooks are applied immediately, and ObjC message
// hooks and memory patches are not supported at all.
@interface HKFishhookBackend : NSObject <HKSubstitutorBackend>
@end

@implementation HKFishhookBackend
- (BOOL)batchingSupported {
    return NO;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    Dl_info info;

    if(dladdr(function, &info) && info.dli_sname) {
        struct rebinding rebinding = {
            info.dli_sname, replacement, old_ptr
        };

        return rebind_symbols(&rebinding, 1) == 0 ? HK_OK : HK_ERR;
    }

    // private symbol: fishhook cannot rebind it
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    return HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)executeHooks:(NSArray<HKHookOperation *> *)hooks {
    // nothing pending: function hooks are applied at hookFunction: time
    return HK_OK;
}

- (HKImageRef)openImage:(NSString *)path {
    return (HKImageRef)dlopen([path fileSystemRepresentation], RTLD_LAZY | RTLD_LOCAL);
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

    int count = _dyld_image_count();

    for(int i = 0; i < count; i++) {
        const char *image_name = _dyld_get_image_name(i);

        if(image_name) {
            void *handle = dlopen(image_name, RTLD_LAZY | RTLD_NOLOAD);

            if(handle) {
                found = dlsym(handle, symbol);
                dlclose(handle);

                if(found) {
                    NSLog(@"[HookKit] found symbol %s in image %s", symbol, image_name);
                    return found;
                }
            }
        }
    }

    return NULL;
}
@end

#pragma mark - HKSubstitutor

@implementation HKSubstitutor {
    id<HKSubstitutorBackend> backend;
    NSMutableArray<HKHookOperation *> *batchHooks;
}

@synthesize types, batching;

+ (id<HKSubstitutorBackend>)defaultBackend {
    if(libhooker_available()) {
        return [HKElleKitBackend new];
    }

    return [HKFishhookBackend new];
}

- (instancetype)init {
    if((self = [super init])) {
        batchHooks = [NSMutableArray new];
        backend = nil;
        types = HK_LIB_NONE;
    }

    return self;
}

- (void)initLibraries {
    if(types == HK_LIB_NONE) {
        backend = [[self class] defaultBackend];
        return;
    }

    if((types & HK_LIB_ELLEKIT) && libhooker_available()) {
        backend = [HKElleKitBackend new];
        return;
    }

    if(types & HK_LIB_FISHHOOK) {
        backend = [HKFishhookBackend new];
        return;
    }

    // requested types are unavailable; fall back to the default backend
    backend = [[self class] defaultBackend];
}

+ (hookkit_lib_t)getAvailableSubstitutorTypes {
    hookkit_lib_t types = HK_LIB_FISHHOOK;

    if(libhooker_available()) {
        types |= HK_LIB_ELLEKIT;
    }

    return types;
}

+ (NSArray<NSDictionary *> *)getSubstitutorTypeInfo:(hookkit_lib_t)types {
    NSMutableArray *result = [NSMutableArray new];

    if((types & HK_LIB_ELLEKIT) && libhooker_available()) {
        [result addObject:@{
            @"id" : @"ellekit",
            @"name" : @"ElleKit",
            @"type" : @(HK_LIB_ELLEKIT)
        }];
    }

    if(types & HK_LIB_FISHHOOK) {
        [result addObject:@{
            @"id" : @"fishhook",
            @"name" : @"fishhook",
            @"type" : @(HK_LIB_FISHHOOK)
        }];
    }

    return [result copy];
}

+ (instancetype)substitutorWithTypes:(hookkit_lib_t)types {
    HKSubstitutor *substitutor = [self new];
    [substitutor setTypes:types];
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
    if(!backend) {
        return HK_ERR_NOT_SUPPORTED;
    }

    if(batching && [backend batchingSupported]) {
        HKHookOperation *hook = [HKHookOperation new];
        [hook setKind:HKHookKindMessage];
        [hook setObjcClass:objcClass];
        [hook setSelector:selector];
        [hook setReplacement:replacement];
        [hook setOrig:old_ptr];
        [batchHooks addObject:hook];
        return HK_OK;
    }

    return [backend hookMessageInClass:objcClass withSelector:selector withReplacement:replacement outOldPtr:old_ptr];
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    if(!backend) {
        return HK_ERR_NOT_SUPPORTED;
    }

    if(batching && [backend batchingSupported]) {
        HKHookOperation *hook = [HKHookOperation new];
        [hook setKind:HKHookKindFunction];
        [hook setFunction:function];
        [hook setReplacement:replacement];
        [hook setOrig:old_ptr];
        [batchHooks addObject:hook];
        return HK_OK;
    }

    return [backend hookFunction:function withReplacement:replacement outOldPtr:old_ptr];
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    if(!backend) {
        return HK_ERR_NOT_SUPPORTED;
    }

    if(batching && [backend batchingSupported]) {
        HKHookOperation *hook = [HKHookOperation new];
        [hook setKind:HKHookKindMemory];
        [hook setTarget:target];
        [hook setData:data];
        [hook setSize:size];
        [batchHooks addObject:hook];
        return HK_OK;
    }

    return [backend hookMemory:target withData:data size:size];
}

- (HKImageRef)openImage:(NSString *)path {
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
    NSMutableArray *outSyms = [NSMutableArray new];

    for(NSString *symbolName in symbolNames) {
        [outSyms addObject:[NSValue valueWithPointer:[self findSymbolInImage:image symbolName:symbolName]]];
    }

    *outSymbols = [outSyms copy];
    return HK_OK;
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    if(!backend) {
        return NULL;
    }

    return [backend findSymbolInImage:image symbolName:symbolName];
}

- (hookkit_status_t)executeHooks {
    if(![batchHooks count]) {
        return HK_OK;
    }

    hookkit_status_t result = [backend executeHooks:batchHooks];
    [batchHooks removeAllObjects];

    return result;
}

- (int)getLibErrno:(hookkit_lib_t *)outType {
    return 0;
}
@end
