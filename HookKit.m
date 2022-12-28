#import "HookKit.h"
#import "HookKit_priv.h"

#import <dlfcn.h>

@implementation HKSubstitutor {
    NSString* libhooker_path;
    void* libhooker_handle;
    @public int (*_LHHookFunctions)(const struct LHFunctionHook* hooks, int count);
    @public int (*_LHPatchMemory)(const struct LHMemoryPatch* patches, int count);
    @public struct libhooker_image* (*_LHOpenImage)(const char* path);
    @public void (*_LHCloseImage)(struct libhooker_image* libhookerImage);
    @public bool (*_LHFindSymbols)(struct libhooker_image* libhookerImage, const char** symbolNames, void** searchSyms, size_t searchSymCount);

    NSString* libblackjack_path;
    void* libblackjack_handle;
    @public enum LIBHOOKER_ERR (*_LBHookMessage)(Class objcClass, SEL selector, void* replacement, void* old_ptr);

    NSString* substitute_path;
    void* substitute_handle;
    @public int (*_substitute_hook_objc_message)(Class klass, SEL selector, void* replacement, void* old_ptr, bool* created_imp_ptr);
    @public int (*_substitute_hook_functions)(const struct substitute_function_hook* hooks, size_t nhooks, struct substitute_function_hook_record** recordp, int options);
    @public void (*_SubHookMemory)(void* target, const void* data, size_t size);
    @public struct substitute_image* (*_substitute_open_image)(const char* filename);
    @public void (*_substitute_close_image)(struct substitute_image* handle);
    @public int (*_substitute_find_private_syms)(struct substitute_image* handle, const char** __restrict names, void** __restrict syms, size_t nsyms);

    NSString* substrate_path;
    void* substrate_handle;
    @public void (*_MSHookMessageEx)(Class _class, SEL sel, IMP imp, IMP* result);
    @public void (*_MSHookFunction)(void* symbol, void* replace, void** result);
    @public void (*_MSHookMemory)(void* target, const void* data, size_t size);
    @public MSImageRef (*_MSGetImageByName)(const char* file);
    @public void (*_MSCloseImage)(MSImageRef);
    @public void* (*_MSFindSymbol)(MSImageRef image, const char* name);
}

- (instancetype)init {
    if((self = [super init])) {
        libhooker_path = ROOT_PATH_NS(@PATH_LIBHOOKER);
        libhooker_handle = dlopen([libhooker_path fileSystemRepresentation], RTLD_NOLOAD|RTLD_LAZY);
        _LHHookFunctions = NULL;
        _LHPatchMemory = NULL;
        _LHOpenImage = NULL;
        _LHCloseImage = NULL;
        _LHFindSymbols = NULL;

        libblackjack_path = ROOT_PATH_NS(@PATH_LIBBLACKJACK);
        libblackjack_handle = dlopen([libblackjack_path fileSystemRepresentation], RTLD_NOLOAD|RTLD_LAZY);
        _LBHookMessage = NULL;

        substitute_path = ROOT_PATH_NS(@PATH_SUBSTITUTE);
        substitute_handle = dlopen([substitute_path fileSystemRepresentation], RTLD_NOLOAD|RTLD_LAZY);
        _substitute_hook_objc_message = NULL;
        _substitute_hook_functions = NULL;
        _SubHookMemory = NULL;
        _substitute_open_image = NULL;
        _substitute_close_image = NULL;
        _substitute_find_private_syms = NULL;

        substrate_path = ROOT_PATH_NS(@PATH_SUBSTRATE);
        substrate_handle = dlopen([substrate_path fileSystemRepresentation], RTLD_NOLOAD|RTLD_LAZY);
        _MSHookMessageEx = NULL;
        _MSHookFunction = NULL;
        _MSHookMemory = NULL;
        _MSGetImageByName = NULL;
        _MSCloseImage = NULL;
        _MSFindSymbol = NULL;

        _types = HK_LIB_NONE;
    }

    return self;
}

- (void)initLibraries {
    if(_types & HK_LIB_LIBHOOKER) {
        if(!libhooker_handle) libhooker_handle = dlopen([libhooker_path fileSystemRepresentation], RTLD_LAZY);
        if(!libblackjack_handle) libblackjack_handle = dlopen([libblackjack_path fileSystemRepresentation], RTLD_LAZY);

        if(libhooker_handle) {
            // resolve symbols
            if(!_LHHookFunctions) _LHHookFunctions = dlsym(libhooker_handle, "LHHookFunctions");
            if(!_LHPatchMemory) _LHPatchMemory = dlsym(libhooker_handle, "LHPatchMemory");
            if(!_LHOpenImage) _LHOpenImage = dlsym(libhooker_handle, "LHOpenImage");
            if(!_LHCloseImage) _LHCloseImage = dlsym(libhooker_handle, "LHCloseImage");
            if(!_LHFindSymbols) _LHFindSymbols = dlsym(libhooker_handle, "LHFindSymbols");
        }

        if(libblackjack_handle) {
            // resolve symbols
            if(!_LBHookMessage) _LBHookMessage = dlsym(libblackjack_handle, "LBHookMessage");
        }
    }

    if(_types & HK_LIB_SUBSTITUTE) {
        if(!substitute_handle) substitute_handle = dlopen([substitute_path fileSystemRepresentation], RTLD_LAZY);

        if(substitute_handle) {
            // resolve symbols
            if(!_substitute_hook_objc_message) _substitute_hook_objc_message = dlsym(substitute_handle, "substitute_hook_objc_message");
            if(!_substitute_hook_functions) _substitute_hook_functions = dlsym(substitute_handle, "substitute_hook_functions");
            if(!_SubHookMemory) _SubHookMemory = dlsym(substitute_handle, "SubHookMemory");
            if(!_substitute_open_image) _substitute_open_image = dlsym(substitute_handle, "substitute_open_image");
            if(!_substitute_close_image) _substitute_close_image = dlsym(substitute_handle, "substitute_close_image");
            if(!_substitute_find_private_syms) _substitute_find_private_syms = dlsym(substitute_handle, "substitute_find_private_syms");
        }
    }

    if(_types & HK_LIB_SUBSTRATE) {
        if(!substrate_handle) substrate_handle = dlopen([substrate_path fileSystemRepresentation], RTLD_LAZY);

        if(substrate_handle) {
            if(!_MSHookMessageEx) _MSHookMessageEx = dlsym(substrate_handle, "MSHookMessageEx");
            if(!_MSHookFunction) _MSHookFunction = dlsym(substrate_handle, "MSHookFunction");
            if(!_MSHookMemory) _MSHookMemory = dlsym(substrate_handle, "MSHookMemory");
            if(!_MSGetImageByName) _MSGetImageByName = dlsym(substrate_handle, "MSGetImageByName");
            if(!_MSCloseImage) _MSCloseImage = dlsym(substrate_handle, "MSCloseImage");
            if(!_MSFindSymbol) _MSFindSymbol = dlsym(substrate_handle, "MSFindSymbol");
        }
    }
}

+ (hookkit_lib_t)getAvailableSubstitutorTypes {
    hookkit_lib_t result = HK_LIB_NONE;

    if([[NSFileManager defaultManager] fileExistsAtPath:ROOT_PATH_NS(@PATH_LIBHOOKER)]) {
        result |= HK_LIB_LIBHOOKER;
    }

    if([[NSFileManager defaultManager] fileExistsAtPath:ROOT_PATH_NS(@PATH_SUBSTITUTE)]) {
        result |= HK_LIB_SUBSTITUTE;
    }

    if([[NSFileManager defaultManager] fileExistsAtPath:ROOT_PATH_NS(@PATH_SUBSTRATE)]) {
        result |= HK_LIB_SUBSTRATE;
    }

    #ifdef fishhook_h
    result |= HK_LIB_FISHHOOK;
    #endif

    return result;
}

+ (NSArray<NSDictionary *> *)getSubstitutorTypeInfo:(hookkit_lib_t)types {
    NSMutableArray* result = [NSMutableArray new];

    if(types & HK_LIB_SUBSTRATE) {
        [result addObject:@{
            @"id" : @"substrate",
            @"name" : @"Cydia Substrate",
            @"type" : [NSNumber numberWithUnsignedInt:HK_LIB_SUBSTRATE],
            @"path" : ROOT_PATH_NS(@PATH_SUBSTRATE)
        }];
    }

    if(types & HK_LIB_SUBSTITUTE) {
        [result addObject:@{
            @"id" : @"substitute",
            @"name" : @"Substitute",
            @"type" : [NSNumber numberWithUnsignedInt:HK_LIB_SUBSTITUTE],
            @"path" : ROOT_PATH_NS(@PATH_SUBSTITUTE)
        }];
    }

    if(types & HK_LIB_LIBHOOKER) {
        [result addObject:@{
            @"id" : @"libhooker",
            @"name" : @"libhooker",
            @"type" : [NSNumber numberWithUnsignedInt:HK_LIB_LIBHOOKER],
            @"path" : ROOT_PATH_NS(@PATH_LIBHOOKER),
            @"extra_path" : @{
                @"libblackjack" : ROOT_PATH_NS(@PATH_LIBBLACKJACK)
            }
        }];
    }

    #ifdef fishhook_h
    if(types & HK_LIB_FISHHOOK) {
        [result addObject:@{
            @"id" : @"fishhook",
            @"name" : @"fishhook",
            @"type" : [NSNumber numberWithUnsignedInt:HK_LIB_FISHHOOK]
        }];
    }
    #endif

    return [result copy];
}

+ (instancetype)substitutorWithTypes:(hookkit_lib_t)types {
    HKSubstitutor* substitutor = [self new];
    [substitutor setTypes:types];
    [substitutor initLibraries];
    return substitutor;
}

+ (instancetype)defaultSubstitutor {
    static dispatch_once_t once;
    static HKSubstitutor* defaultSubstitutor;

    dispatch_once(&once, ^{
        defaultSubstitutor = [self substitutorWithTypes:[self getAvailableSubstitutorTypes]];
    });

    return defaultSubstitutor;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    hookkit_status_t result = HK_ERR;

    if(_types & HK_LIB_LIBHOOKER) {
        if(_LBHookMessage) {
            if(_LBHookMessage(objcClass, selector, replacement, old_ptr) == LIBHOOKER_OK) {
                return HK_OK;
            } else {
                // handle libhooker error codes

                return result;
            }
        }
    }

    if(_types & HK_LIB_SUBSTITUTE) {
        if(_substitute_hook_objc_message) {
            if(_substitute_hook_objc_message(objcClass, selector, replacement, (void *)old_ptr, NULL) == SUBSTITUTE_OK) {
                return HK_OK;
            } else {
                // handle substitute error codes

                return result;
            }
        }
    }

    if(_types & HK_LIB_SUBSTRATE) {
        if(_MSHookMessageEx) {
            _MSHookMessageEx(objcClass, selector, replacement, (IMP *)old_ptr);
            return HK_OK;
        }
    }
    
    #ifdef fishhook_h
    if(_types & HK_LIB_FISHHOOK) {
        
    }
    #endif

    if(result == HK_ERR) {
        result |= HK_ERR_NOT_SUPPORTED;
    }

    return result;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    hookkit_status_t result = HK_ERR;

    if(_types & HK_LIB_LIBHOOKER) {
        if(_LHHookFunctions) {
            struct LHFunctionHook hook = {
                function, replacement, (void *)old_ptr, NULL
            };

            if(_LHHookFunctions(&hook, 1) == 1) {
                return HK_OK;
            } else {
                // handle libhooker error codes

                return result;
            }
        }
    }
    
    if(_types & HK_LIB_SUBSTITUTE) {
        if(_substitute_hook_functions) {
            struct substitute_function_hook hook = {
                function, replacement, (void *)old_ptr, 0
            };

            if(_substitute_hook_functions(&hook, 1, NULL, 0) == SUBSTITUTE_OK) {
                return HK_OK;
            } else {
                // handle substitute error codes

                return result;
            }
        }
    }
    
    if(_types & HK_LIB_SUBSTRATE) {
        if(_MSHookFunction) {
            _MSHookFunction(function, replacement, old_ptr);
            return HK_OK;
        }
    }
    
    #ifdef fishhook_h
    if(_types & HK_LIB_FISHHOOK) {
        Dl_info info;
        if(dladdr(function, &info)) {
            if(rebind_symbols((struct rebinding[1]){{info.dli_sname, replacement, old_ptr}}, 1)) {
                return HK_OK;
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

    if(_types & HK_LIB_LIBHOOKER) {
        if(_LHPatchMemory) {
            struct LHMemoryPatch hook = {
                target, data, size, 0
            };

            if(_LHPatchMemory(&hook, 1) == 1) {
                return HK_OK;
            } else {
                // handle libhooker error codes

                return result;
            }
        }
    }
    
    if(_types & HK_LIB_SUBSTITUTE) {
        if(_SubHookMemory) {
            _SubHookMemory(target, data, size);
            return HK_OK;
        }
    }
    
    if(_types & HK_LIB_SUBSTRATE) {
        if(_MSHookMemory) {
            _MSHookMemory(target, data, size);
            return HK_OK;
        }
    }

    if(result == HK_ERR) {
        result |= HK_ERR_NOT_SUPPORTED;
    }

    return result;
}

- (HKImageRef)openImage:(NSString *)path {
    if(_types & HK_LIB_LIBHOOKER) {
        if(_LHOpenImage) {
            return (HKImageRef)_LHOpenImage([path fileSystemRepresentation]);
        }
    }
    
    if(_types & HK_LIB_SUBSTITUTE) {
        if(_substitute_open_image) {
            return (HKImageRef)_substitute_open_image([path fileSystemRepresentation]);
        }
    }
    
    if(_types & HK_LIB_SUBSTRATE) {
        if(_MSGetImageByName) {
            return (HKImageRef)_MSGetImageByName([path fileSystemRepresentation]);
        }
    }

    return NULL;
}

- (void)closeImage:(HKImageRef)image {
    if(!image) {
        return;
    }

    if(_types & HK_LIB_LIBHOOKER) {
        if(_LHCloseImage) {
            _LHCloseImage((struct libhooker_image *)image);
            return;
        }
    }
    
    if(_types & HK_LIB_SUBSTITUTE) {
        if(_substitute_close_image) {
            _substitute_close_image((struct substitute_image *)image);
            return;
        }
    }
    
    if(_types & HK_LIB_SUBSTRATE) {
        if(_MSCloseImage) {
            _MSCloseImage((MSImageRef)image);
            return;
        }
    }
}

- (hookkit_status_t)findSymbolsInImage:(HKImageRef)image symbolNames:(NSArray<NSString *> *)symbolNames outSymbols:(NSArray<NSValue *> **)outSymbols {
    hookkit_status_t result = HK_ERR;

    if(image != NULL) {
        // libhooker and substitute do not natively handle a NULL value (all images) for image. Keep that to substrate-only as a compatibility layer.

        if(_types & HK_LIB_LIBHOOKER) {
            if(_LHFindSymbols) {
                
            }
        }
        
        if(_types & HK_LIB_SUBSTITUTE) {
            if(_substitute_find_private_syms) {

            }
        }
    }
    
    if(_types & HK_LIB_SUBSTRATE) {
        // Substrate does not handle multiple symbols, so just manually loop.
        if(_MSFindSymbol) {
            NSMutableArray* syms = [NSMutableArray new];

            for(NSString* symbolName in symbolNames) {
                void* sym = _MSFindSymbol((MSImageRef)image, [symbolName UTF8String]);
                [syms addObject:[NSValue valueWithPointer:sym]];
            }

            *outSymbols = [syms copy];
            return HK_OK;
        }
    }

    if(result == HK_ERR) {
        result |= HK_ERR_NOT_SUPPORTED;
    }

    return result;
}

- (hookkit_status_t)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName outSymbol:(void **)outSymbol {
    NSArray<NSValue *>* syms = nil;
    hookkit_status_t result = [self findSymbolsInImage:image symbolNames:@[symbolName] outSymbols:&syms];
    *outSymbol = [syms[0] pointerValue];
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

    if(!didFunctions && [substitutor types] & HK_LIB_LIBHOOKER) {
        int (*_LHHookFunctions)(const struct LHFunctionHook* hooks, int count) = substitutor->_LHHookFunctions;
        
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

    if(!didFunctions && [substitutor types] & HK_LIB_SUBSTITUTE) {
        int (*_substitute_hook_functions)(const struct substitute_function_hook* hooks, size_t nhooks, struct substitute_function_hook_record** recordp, int options) = substitutor->_substitute_hook_functions;

        if(_substitute_hook_functions) {
            NSMutableData* hooks = [NSMutableData new];

            for(HKFunctionHook* hkhook in functionHooks) {
                struct substitute_function_hook hook = {
                    [hkhook function], [hkhook replacement], [hkhook orig], 0
                };

                [hooks appendBytes:&hook length:sizeof(struct substitute_function_hook)];
            }

            _substitute_hook_functions([hooks bytes], [functionHooks count], NULL, 0);
            didFunctions = YES;
        }
    }

    if(!didFunctions && [substitutor types] & HK_LIB_SUBSTRATE) {
        void (*_MSHookFunction)(void* symbol, void* replace, void** result) = substitutor->_MSHookFunction;
        
        if(_MSHookFunction) {
            for(HKFunctionHook* hkhook in functionHooks) {
                _MSHookFunction([hkhook function], [hkhook replacement], [hkhook orig]);
            }

            didFunctions = YES;
        }
    }

    #ifdef fishhook_h
    if(!didFunctions && [substitutor types] & HK_LIB_FISHHOOK) {
        NSMutableData* hooks = [NSMutableData new];

        for(HKFunctionHook* hkhook in functionHooks) {
            Dl_info info;
            if(dladdr([hkhook function], &info)) {
                struct rebinding hook = {
                    info.dli_sname, [hkhook replacement], [hkhook orig]
                };

                [hooks appendBytes:&hook length:sizeof(struct rebinding)];
            }
        }

        rebind_symbols((struct rebinding *)[hooks bytes], [functionHooks count]);
        didFunctions = YES;
    }
    #endif

    if(!didMemory && [substitutor types] & HK_LIB_LIBHOOKER) {
        int (*_LHPatchMemory)(const struct LHMemoryPatch* patches, int count) = substitutor->_LHPatchMemory;
        
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

    if(!didMemory && [substitutor types] & HK_LIB_SUBSTITUTE) {
        void (*_SubHookMemory)(void* target, const void* data, size_t size) = substitutor->_SubHookMemory;
        
        if(_SubHookMemory) {
            for(HKMemoryHook* hkhook in memoryHooks) {
                _SubHookMemory([hkhook target], [hkhook data], [hkhook size]);
            }

            didMemory = YES;
        }
    }

    if(!didMemory && [substitutor types] & HK_LIB_SUBSTRATE) {
        void (*_MSHookMemory)(void* target, const void* data, size_t size) = substitutor->_MSHookMemory;
        
        if(_MSHookMemory) {
            for(HKMemoryHook* hkhook in memoryHooks) {
                _MSHookMemory([hkhook target], [hkhook data], [hkhook size]);
            }

            didMemory = YES;
        }
    }

    if(didFunctions && didMemory) {
        result = HK_OK;
    }

    if(result == HK_ERR) {
        result |= HK_ERR_NOT_SUPPORTED;
    }

    return result;
}
@end
