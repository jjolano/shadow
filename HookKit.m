#import "HookKit.h"
#import "HookKit_priv.h"

#import <dlfcn.h>

@implementation HKSubstitutor {
    NSString* libhooker_path;
    NSString* libblackjack_path;
    NSString* substitute_path;
    NSString* substrate_path;
}

- (instancetype)init {
    if((self = [super init])) {
        libhooker_path = ROOT_PATH_NS(@PATH_LIBHOOKER);
        libblackjack_path = ROOT_PATH_NS(@PATH_LIBBLACKJACK);
        substitute_path = ROOT_PATH_NS(@PATH_SUBSTITUTE);
        substrate_path = ROOT_PATH_NS(@PATH_SUBSTRATE);

        _types = HK_LIB_NONE;
    }

    return self;
}

+ (hookkit_lib_t)getAvailableSubstitutorTypes {
    NSString* libhooker_path = ROOT_PATH_NS(@PATH_LIBHOOKER);
    NSString* libblackjack_path = ROOT_PATH_NS(@PATH_LIBBLACKJACK);
    NSString* substitute_path = ROOT_PATH_NS(@PATH_SUBSTITUTE);
    NSString* substrate_path = ROOT_PATH_NS(@PATH_SUBSTRATE);

    hookkit_lib_t result = HK_LIB_NONE;

    if([[NSFileManager defaultManager] fileExistsAtPath:libhooker_path]) {
        result |= HK_LIB_LIBHOOKER;
    }

    if([[NSFileManager defaultManager] fileExistsAtPath:libblackjack_path]) {
        result |= HK_LIB_LIBBLACKJACK;
    }

    if([[NSFileManager defaultManager] fileExistsAtPath:substitute_path]) {
        result |= HK_LIB_SUBSTITUTE;
    }

    if([[NSFileManager defaultManager] fileExistsAtPath:substrate_path]) {
        result |= HK_LIB_SUBSTRATE;
    }

    #ifdef fishhook_h
    result |= HK_LIB_FISHHOOK;
    #endif

    return result;
}

+ (instancetype)substitutorWithTypes:(hookkit_lib_t)types {
    HKSubstitutor* substitutor = [self new];
    [substitutor setTypes:types];
    return substitutor;
}

+ (instancetype)defaultSubstitutor {
    static dispatch_once_t once;
    static HKSubstitutor* defaultSubstitutor;

    dispatch_once(&once, ^{
        defaultSubstitutor = [self new];
        [defaultSubstitutor setTypes:[self getAvailableSubstitutorTypes]];
    });

    return defaultSubstitutor;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    hookkit_status_t result = HK_ERR;
    void* handle = NULL;

    if(result == HK_ERR && (_types & HK_LIB_LIBBLACKJACK) == HK_LIB_LIBBLACKJACK && (handle = dlopen([libblackjack_path fileSystemRepresentation], RTLD_LAZY))) {
        static enum LIBHOOKER_ERR (*_LBHookMessage)(Class objcClass, SEL selector, void* replacement, void* old_ptr) = NULL;
        if(!_LBHookMessage) _LBHookMessage = dlsym(handle, "LBHookMessage");
        if(_LBHookMessage) {
            if(_LBHookMessage(objcClass, selector, replacement, old_ptr) == LIBHOOKER_OK) {
                result = HK_OK;
            }
        }

        dlclose(handle);
    }

    if(result == HK_ERR && (_types & HK_LIB_SUBSTITUTE) == HK_LIB_SUBSTITUTE && (handle = dlopen([substitute_path fileSystemRepresentation], RTLD_LAZY))) {
        static int (*_substitute_hook_objc_message)(Class klass, SEL selector, void* replacement, void* old_ptr, bool* created_imp_ptr) = NULL;
        if(!_substitute_hook_objc_message) _substitute_hook_objc_message = dlsym(handle, "substitute_hook_objc_message");
        if(_substitute_hook_objc_message) {
            if(_substitute_hook_objc_message(objcClass, selector, replacement, (void *)old_ptr, NULL) == SUBSTITUTE_OK) {
                result = HK_OK;
            }
        }

        dlclose(handle);
    }

    if(result == HK_ERR && (_types & HK_LIB_SUBSTRATE) == HK_LIB_SUBSTRATE && (handle = dlopen([substrate_path fileSystemRepresentation], RTLD_LAZY))) {
        static void (*_MSHookMessageEx)(Class _class, SEL sel, IMP imp, IMP* result) = NULL;
        if(!_MSHookMessageEx) _MSHookMessageEx = dlsym(handle, "MSHookMessageEx");
        if(_MSHookMessageEx) {
            _MSHookMessageEx(objcClass, selector, replacement, (IMP *)old_ptr);
            result = HK_OK;
        }

        dlclose(handle);
    }
    
    #ifdef fishhook_h
    if(result == HK_ERR && (_types & HK_LIB_FISHHOOK) == HK_LIB_FISHHOOK) {
        
    }
    #endif

    if(result == HK_ERR) {
        result |= HK_ERR_NOT_SUPPORTED;
    }

    return result;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    hookkit_status_t result = HK_ERR;
    void* handle = NULL;

    if(result == HK_ERR && (_types & HK_LIB_LIBHOOKER) == HK_LIB_LIBHOOKER && (handle = dlopen([libhooker_path fileSystemRepresentation], RTLD_LAZY))) {
        struct LHFunctionHook hook = {
            function, replacement, (void *)old_ptr, NULL
        };

        static int (*_LHHookFunctions)(const struct LHFunctionHook* hooks, int count) = NULL;
        if(!_LHHookFunctions) _LHHookFunctions = dlsym(handle, "LHHookFunctions");
        if(_LHHookFunctions) {
            if(_LHHookFunctions(&hook, 1) == 1) {
                result = HK_OK;
            }
        }

        dlclose(handle);
    }
    
    if(result == HK_ERR && (_types & HK_LIB_SUBSTITUTE) == HK_LIB_SUBSTITUTE && (handle = dlopen([substitute_path fileSystemRepresentation], RTLD_LAZY))) {
        struct substitute_function_hook hook = {
            function, replacement, (void *)old_ptr, 0
        };

        static int (*_substitute_hook_functions)(const struct substitute_function_hook* hooks, size_t nhooks, struct substitute_function_hook_record** recordp, int options) = NULL;
        if(!_substitute_hook_functions) _substitute_hook_functions = dlsym(handle, "substitute_hook_functions");
        if(_substitute_hook_functions) {
            if(_substitute_hook_functions(&hook, 1, NULL, 0) == SUBSTITUTE_OK) {
                result = HK_OK;
            }
        }

        dlclose(handle);
    }
    
    if(result == HK_ERR && (_types & HK_LIB_SUBSTRATE) == HK_LIB_SUBSTRATE && (handle = dlopen([substrate_path fileSystemRepresentation], RTLD_LAZY))) {
        static void (*_MSHookFunction)(void* symbol, void* replace, void** result) = NULL;
        if(!_MSHookFunction) _MSHookFunction = dlsym(handle, "MSHookFunction");
        if(_MSHookFunction) {
            _MSHookFunction(function, replacement, old_ptr);
            result = HK_OK;
        }

        dlclose(handle);
    }
    
    #ifdef fishhook_h
    if(result == HK_ERR && (_types & HK_LIB_FISHHOOK) == HK_LIB_FISHHOOK) {
        Dl_info info;
        if(dladdr(function, &info)) {
            if(rebind_symbols((struct rebinding[1]){{info.dli_sname, replacement, old_ptr}}, 1)) {
                result = HK_OK;
            }
        }
    }
    #endif

    if(result == HK_ERR) {
        result |= HK_ERR_NOT_SUPPORTED;
    }

    return result;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    hookkit_status_t result = HK_ERR;
    void* handle = NULL;

    if(result == HK_ERR && (_types & HK_LIB_LIBHOOKER) == HK_LIB_LIBHOOKER && (handle = dlopen([libhooker_path fileSystemRepresentation], RTLD_LAZY))) {
        struct LHMemoryPatch hook = {
            target, data, size, 0
        };

        static int (*_LHPatchMemory)(const struct LHMemoryPatch* patches, int count) = NULL;
        if(!_LHPatchMemory) _LHPatchMemory = dlsym(handle, "LHPatchMemory");
        if(_LHPatchMemory) {
            if(_LHPatchMemory(&hook, 1) == 1) {
                result = HK_OK;
            }
        }

        dlclose(handle);
    }
    
    if(result == HK_ERR && (_types & HK_LIB_SUBSTITUTE) == HK_LIB_SUBSTITUTE && (handle = dlopen([substitute_path fileSystemRepresentation], RTLD_LAZY))) {
        // SubHookMemory is just a shim to MSHookMemory, so let's just use that.
        static void (*_SubHookMemory)(void* target, const void* data, size_t size) = NULL;
        if(!_SubHookMemory) _SubHookMemory = dlsym(handle, "SubHookMemory");
        if(_SubHookMemory) {
            _SubHookMemory(target, data, size);
            result = HK_OK;
        }

        dlclose(handle);
    }
    
    if(result == HK_ERR && (_types & HK_LIB_SUBSTRATE) == HK_LIB_SUBSTRATE && (handle = dlopen([substrate_path fileSystemRepresentation], RTLD_LAZY))) {
        static void (*_MSHookMemory)(void* target, const void* data, size_t size) = NULL;
        if(!_MSHookMemory) _MSHookMemory = dlsym(handle, "MSHookMemory");
        if(_MSHookMemory) {
            _MSHookMemory(target, data, size);
            result = HK_OK;
        }

        dlclose(handle);
    }

    if(result == HK_ERR) {
        result |= HK_ERR_NOT_SUPPORTED;
    }

    return result;
}

- (HKImageRef)openImage:(NSString *)path {
    HKImageRef result = NULL;
    void* handle = NULL;

    if(result == NULL && (_types & HK_LIB_LIBHOOKER) == HK_LIB_LIBHOOKER && (handle = dlopen([libhooker_path fileSystemRepresentation], RTLD_LAZY))) {
        static struct libhooker_image* (*_LHOpenImage)(const char* path) = NULL;
        if(!_LHOpenImage) _LHOpenImage = dlsym(handle, "LHOpenImage");
        if(_LHOpenImage) {
            result = (HKImageRef)_LHOpenImage([path fileSystemRepresentation]);
        }

        dlclose(handle);
    }
    
    if(result == NULL && (_types & HK_LIB_SUBSTITUTE) == HK_LIB_SUBSTITUTE && (handle = dlopen([substitute_path fileSystemRepresentation], RTLD_LAZY))) {
        static struct substitute_image* (*_substitute_open_image)(const char* filename) = NULL;
        if(!_substitute_open_image) _substitute_open_image = dlsym(handle, "substitute_open_image");
        if(_substitute_open_image) {
            result = (HKImageRef)_substitute_open_image([path fileSystemRepresentation]);
        }

        dlclose(handle);
    }
    
    if(result == NULL && (_types & HK_LIB_SUBSTRATE) == HK_LIB_SUBSTRATE && (handle = dlopen([substrate_path fileSystemRepresentation], RTLD_LAZY))) {
        static MSImageRef (*_MSGetImageByName)(const char* file) = NULL;
        if(!_MSGetImageByName) _MSGetImageByName = dlsym(handle, "MSGetImageByName");
        if(_MSGetImageByName) {
            result = (HKImageRef)_MSGetImageByName([path fileSystemRepresentation]);
        }

        dlclose(handle);
    }

    return result;
}

- (void)closeImage:(HKImageRef)image {
    void* handle = NULL;

    if(image != NULL && (_types & HK_LIB_LIBHOOKER) == HK_LIB_LIBHOOKER && (handle = dlopen([libhooker_path fileSystemRepresentation], RTLD_LAZY))) {
        static void (*_LHCloseImage)(struct libhooker_image* libhookerImage) = NULL;
        if(!_LHCloseImage) _LHCloseImage = dlsym(handle, "LHCloseImage");
        if(_LHCloseImage) {
            _LHCloseImage((struct libhooker_image *)image);
            image = NULL;
        }

        dlclose(handle);
    }
    
    if(image != NULL && (_types & HK_LIB_SUBSTITUTE) == HK_LIB_SUBSTITUTE && (handle = dlopen([substitute_path fileSystemRepresentation], RTLD_LAZY))) {
        static void (*_substitute_close_image)(struct substitute_image* handle) = NULL;
        if(!_substitute_close_image) _substitute_close_image = dlsym(handle, "substitute_close_image");
        if(_substitute_close_image) {
            _substitute_close_image((struct substitute_image *)image);
            image = NULL;
        }

        dlclose(handle);
    }
    
    if(image != NULL && (_types & HK_LIB_SUBSTRATE) == HK_LIB_SUBSTRATE && (handle = dlopen([substrate_path fileSystemRepresentation], RTLD_LAZY))) {
        static void (*_MSCloseImage)(MSImageRef) = NULL;
        if(!_MSCloseImage) _MSCloseImage = dlsym(handle, "MSCloseImage");
        if(_MSCloseImage) {
            _MSCloseImage((MSImageRef)image);
            image = NULL;
        }

        dlclose(handle);
    }
}

- (hookkit_status_t)findSymbolsInImage:(HKImageRef)image symbolNames:(NSArray<NSString *> *)symbolNames outSymbols:(NSArray<NSNumber *> **)outSymbols {
    hookkit_status_t result = HK_ERR;
    void* handle = NULL;

    if(result == HK_ERR && (_types & HK_LIB_LIBHOOKER) == HK_LIB_LIBHOOKER && (handle = dlopen([libhooker_path fileSystemRepresentation], RTLD_LAZY))) {
        static bool (*_LHFindSymbols)(struct libhooker_image* libhookerImage, const char** symbolNames, void** searchSyms, size_t searchSymCount) = NULL;
        if(!_LHFindSymbols) _LHFindSymbols = dlsym(handle, "LHFindSymbols");
        if(_LHFindSymbols) {

        }

        dlclose(handle);
    }
    
    if(result == HK_ERR && (_types & HK_LIB_SUBSTITUTE) == HK_LIB_SUBSTITUTE && (handle = dlopen([substitute_path fileSystemRepresentation], RTLD_LAZY))) {
        static int (*_substitute_find_private_syms)(struct substitute_image* handle, const char** __restrict names, void** __restrict syms, size_t nsyms) = NULL;
        if(!_substitute_find_private_syms) _substitute_find_private_syms = dlsym(handle, "substitute_find_private_syms");
        if(_substitute_find_private_syms) {

        }

        dlclose(handle);
    }
    
    if(result == HK_ERR && (_types & HK_LIB_SUBSTRATE) == HK_LIB_SUBSTRATE && (handle = dlopen([substrate_path fileSystemRepresentation], RTLD_LAZY))) {
        // Substrate does not handle multiple symbols, so just manually loop.
        static void* (*_MSFindSymbol)(MSImageRef image, const char* name) = NULL;
        if(!_MSFindSymbol) _MSFindSymbol = dlsym(handle, "MSFindSymbol");
        if(_MSFindSymbol) {
            NSMutableArray* syms = [NSMutableArray new];

            for(NSString* symbolName in symbolNames) {
                void* sym = _MSFindSymbol((MSImageRef)image, [symbolName UTF8String]);
                [syms addObject:@((unsigned long)sym)];
            }

            *outSymbols = [syms copy];
        }

        dlclose(handle);
    }

    if(result == HK_ERR) {
        result |= HK_ERR_NOT_SUPPORTED;
    }

    return result;
}

- (hookkit_status_t)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName outSymbol:(void **)outSymbol {
    NSArray<NSNumber *>* syms = nil;
    hookkit_status_t result = [self findSymbolsInImage:image symbolNames:@[symbolName] outSymbols:&syms];
    *outSymbol = (void *)[syms[0] unsignedLongValue];
    return result;
}
@end

@implementation HKFunctionHook
@end

@implementation HKMemoryHook
@end

@implementation HKBatchHook {
    NSMutableArray<HKFunctionHook *>* functionHooks;
    NSMutableArray<HKMemoryHook *>* memoryHooks;
}

- (instancetype)init {
    if((self = [super init])) {
        functionHooks = [NSMutableArray new];
        memoryHooks = [NSMutableArray new];
    }

    return self;
}

- (void)addFunctionHook:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    HKFunctionHook* hook = [HKFunctionHook new];
    [hook setFunction:function];
    [hook setReplacement:replacement];
    [hook setOrig:old_ptr];

    [functionHooks addObject:hook];
}

- (void)addMemoryHook:(void *)target withData:(const void *)data size:(size_t)size {
    HKMemoryHook* hook = [HKMemoryHook new];
    [hook setTarget:target];
    [hook setData:data];
    [hook setSize:size];

    [memoryHooks addObject:hook];
}

- (hookkit_status_t)performHooksWithSubstitutor:(HKSubstitutor *)substitutor {
    hookkit_status_t result = HK_ERR;

    BOOL didFunctions = ([functionHooks count] == 0);
    BOOL didMemory = ([memoryHooks count] == 0);

    void* handle = NULL;

    if((!didFunctions || !didMemory) && result == HK_ERR && ([substitutor types] & HK_LIB_LIBHOOKER) == HK_LIB_LIBHOOKER && (handle = dlopen(ROOT_PATH_C(PATH_LIBHOOKER), RTLD_LAZY))) {
        if(!didFunctions) {
            static int (*_LHHookFunctions)(const struct LHFunctionHook* hooks, int count) = NULL;
            if(!_LHHookFunctions) _LHHookFunctions = dlsym(handle, "LHHookFunctions");
            if(_LHHookFunctions) {
                NSMutableData* hooks = [NSMutableData new];

                for(HKFunctionHook* hkhook in functionHooks) {
                    struct LHFunctionHook hook = {
                        [hkhook function], [hkhook replacement], [hkhook orig], 0
                    };

                    [hooks appendBytes:&hook length:sizeof(struct LHFunctionHook)];
                }

                if(_LHHookFunctions([hooks bytes], [functionHooks count])) {
                    didFunctions = YES;
                }
            }
        }

        if(!didMemory) {
            static int (*_LHPatchMemory)(const struct LHMemoryPatch* patches, int count) = NULL;
            if(!_LHPatchMemory) _LHPatchMemory = dlsym(handle, "LHPatchMemory");
            if(_LHPatchMemory) {
                NSMutableData* hooks = [NSMutableData new];

                for(HKMemoryHook* hkhook in memoryHooks) {
                    struct LHMemoryPatch hook = {
                        [hkhook target], [hkhook data], [hkhook size], 0
                    };

                    [hooks appendBytes:&hook length:sizeof(struct LHMemoryPatch)];
                }

                if(_LHPatchMemory([hooks bytes], [memoryHooks count])) {
                    didMemory = YES;
                }
            }
        }

        dlclose(handle);
    }
    
    if((!didFunctions || !didMemory) && result == HK_ERR && ([substitutor types] & HK_LIB_SUBSTITUTE) == HK_LIB_SUBSTITUTE && (handle = dlopen(ROOT_PATH_C(PATH_SUBSTITUTE), RTLD_LAZY))) {
        if(!didFunctions) {
            static int (*_substitute_hook_functions)(const struct substitute_function_hook* hooks, size_t nhooks, struct substitute_function_hook_record** recordp, int options) = NULL;
            if(!_substitute_hook_functions) _substitute_hook_functions = dlsym(handle, "substitute_hook_functions");
            if(_substitute_hook_functions) {
                NSMutableData* hooks = [NSMutableData new];

                for(HKFunctionHook* hkhook in functionHooks) {
                    struct substitute_function_hook hook = {
                        [hkhook function], [hkhook replacement], [hkhook orig], 0
                    };

                    [hooks appendBytes:&hook length:sizeof(struct substitute_function_hook)];
                }

                if(_substitute_hook_functions([hooks bytes], [functionHooks count], NULL, 0) == SUBSTITUTE_OK) {
                    didFunctions = YES;
                }
            }
        }

        if(!didMemory) {
            static void (*_SubHookMemory)(void* target, const void* data, size_t size) = NULL;
            if(!_SubHookMemory) _SubHookMemory = dlsym(handle, "SubHookMemory");
            if(_SubHookMemory) {
                for(HKMemoryHook* hkhook in memoryHooks) {
                    _SubHookMemory([hkhook target], [hkhook data], [hkhook size]);
                }

                didMemory = YES;
            }
        }

        dlclose(handle);
    }
    
    if((!didFunctions || !didMemory) && result == HK_ERR && ([substitutor types] & HK_LIB_SUBSTRATE) == HK_LIB_SUBSTRATE && (handle = dlopen(ROOT_PATH_C(PATH_SUBSTRATE), RTLD_LAZY))) {
        // Substrate doesn't support batching, so loop manually

        if(!didFunctions) {
            static void (*_MSHookFunction)(void* symbol, void* replace, void** result) = NULL;
            if(!_MSHookFunction) _MSHookFunction = dlsym(handle, "MSHookFunction");
            if(_MSHookFunction) {
                for(HKFunctionHook* hkhook in functionHooks) {
                    _MSHookFunction([hkhook function], [hkhook replacement], [hkhook orig]);
                }

                didFunctions = YES;
            }
        }

        if(!didMemory) {
            static void (*_MSHookMemory)(void* target, const void* data, size_t size) = NULL;
            if(!_MSHookMemory) _MSHookMemory = dlsym(handle, "MSHookMemory");
            if(_MSHookMemory) {
                for(HKMemoryHook* hkhook in memoryHooks) {
                    _MSHookMemory([hkhook target], [hkhook data], [hkhook size]);
                }

                didMemory = YES;
            }
        }

        dlclose(handle);
    }
    
    #ifdef fishhook_h
    if(!didFunctions && result == HK_ERR && ([substitutor types] & HK_LIB_FISHHOOK) == HK_LIB_FISHHOOK) {
        for(HKFunctionHook* hkhook in functionHooks) {
            Dl_info info;
            if(dladdr([hkhook function], &info)) {
                rebind_symbols((struct rebinding[1]){{info.dli_sname, [hkhook replacement], [hkhook orig]}}, 1);
            }
        }

        didFunctions = YES;
    }
    #endif

    if(didFunctions && didMemory) {
        result = HK_OK;
    }

    if(result == HK_ERR) {
        result |= HK_ERR_NOT_SUPPORTED;
    }

    return result;
}
@end
