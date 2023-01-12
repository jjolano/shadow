#import "HookKit.h"
#import "HookKit_priv.h"

#import <dlfcn.h>

@implementation HKFunctionHook
@end

@implementation HKMemoryHook
@end

@implementation HKSubstitutor {
    NSArray<HKFunctionHook *>* functionHooks;
    NSArray<HKMemoryHook *>* memoryHooks;

    int lib_errno;
    hookkit_lib_t lib_errno_type;

    NSString* libellekit_path;
    void* libellekit_handle;

    NSString* libhooker_path;
    void* libhooker_handle;
    int (*_LHHookFunctions)(const struct LHFunctionHook* hooks, int count);
    int (*_LHPatchMemory)(const struct LHMemoryPatch* patches, int count);
    struct libhooker_image* (*_LHOpenImage)(const char* path);
    void (*_LHCloseImage)(struct libhooker_image* libhookerImage);
    bool (*_LHFindSymbols)(struct libhooker_image* libhookerImage, const char** symbolNames, void** searchSyms, size_t searchSymCount);

    NSString* libblackjack_path;
    void* libblackjack_handle;
    enum LIBHOOKER_ERR (*_LBHookMessage)(Class objcClass, SEL selector, void* replacement, void* old_ptr);

    NSString* substitute_path;
    void* substitute_handle;
    int (*_substitute_hook_objc_message)(Class klass, SEL selector, void* replacement, void* old_ptr, bool* created_imp_ptr);
    int (*_substitute_hook_functions)(const struct substitute_function_hook* hooks, size_t nhooks, struct substitute_function_hook_record** recordp, int options);
    void (*_SubHookMemory)(void* target, const void* data, size_t size);
    struct substitute_image* (*_substitute_open_image)(const char* filename);
    void (*_substitute_close_image)(struct substitute_image* handle);
    int (*_substitute_find_private_syms)(struct substitute_image* handle, const char** __restrict names, void** __restrict syms, size_t nsyms);

    NSString* substrate_path;
    void* substrate_handle;
    void (*_MSHookMessageEx)(Class _class, SEL sel, IMP imp, IMP* result);
    void (*_MSHookFunction)(void* symbol, void* replace, void** result);
    void (*_MSHookMemory)(void* target, const void* data, size_t size);
    MSImageRef (*_MSGetImageByName)(const char* file);
    void (*_MSCloseImage)(MSImageRef);
    void* (*_MSFindSymbol)(MSImageRef image, const char* name);
}

- (instancetype)init {
    if((self = [super init])) {
        functionHooks = [NSArray new];
        memoryHooks = [NSArray new];

        lib_errno = 0;
        lib_errno_type = HK_LIB_NONE;

        libellekit_path = ROOT_PATH_NS(@PATH_ELLEKIT);
        libellekit_handle = dlopen([libellekit_path fileSystemRepresentation], RTLD_NOLOAD|RTLD_LAZY);

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

        if(!substitute_handle) {
            substitute_path = ROOT_PATH_NS(@PATH_SUBSTITUTE2);
            substitute_handle = dlopen([substitute_path fileSystemRepresentation], RTLD_NOLOAD|RTLD_LAZY);
        }

        _substitute_hook_objc_message = NULL;
        _substitute_hook_functions = NULL;
        _SubHookMemory = NULL;
        _substitute_open_image = NULL;
        _substitute_close_image = NULL;
        _substitute_find_private_syms = NULL;

        substrate_path = ROOT_PATH_NS(@PATH_SUBSTRATE);
        substrate_handle = dlopen([substrate_path fileSystemRepresentation], RTLD_NOLOAD|RTLD_LAZY);

        if(!substrate_handle) {
            substrate_path = ROOT_PATH_NS(@PATH_SUBSTRATE2);
            substrate_handle = dlopen([substrate_path fileSystemRepresentation], RTLD_NOLOAD|RTLD_LAZY);
        }

        _MSHookMessageEx = MSHookMessageEx;
        _MSHookFunction = MSHookFunction;
        _MSHookMemory = MSHookMemory;
        _MSGetImageByName = MSGetImageByName;
        _MSCloseImage = MSCloseImage;
        _MSFindSymbol = MSFindSymbol;

        _types = HK_LIB_NONE;
        _batching = NO;
    }

    return self;
}

- (void)initLibraries {
    if(_types == HK_LIB_NONE) {
        if(libellekit_handle) {
            libhooker_handle = libellekit_handle;
            libblackjack_handle = libellekit_handle;
            substrate_handle = libellekit_handle;
        }

        if(libhooker_handle || libblackjack_handle) {
            _types |= HK_LIB_LIBHOOKER;
        }

        if(substitute_handle) {
            _types |= HK_LIB_SUBSTITUTE;
        }

        if(substrate_handle) {
            _types |= HK_LIB_SUBSTRATE;
        }

        #ifdef fishhook_h
        _types |= HK_LIB_FISHHOOK;
        #endif

        #ifdef dobby_h
        _types |= HK_LIB_DOBBY;
        #endif
    }

    if(_types == HK_LIB_ELLEKIT) {
        // ellekit implements both libhooker and substrate APIs
        // should be able to just enable both types and point handles to ellekit for symbol resolving later

        if(libhooker_handle) dlclose(libhooker_handle);
        if(libblackjack_handle) dlclose(libblackjack_handle);
        if(substrate_handle) dlclose(substrate_handle);
        
        if(!libellekit_handle) libellekit_handle = dlopen([libellekit_path fileSystemRepresentation], RTLD_LAZY);

        libhooker_handle = libellekit_handle;
        libblackjack_handle = libellekit_handle;
        substrate_handle = libellekit_handle;

        _types |= HK_LIB_LIBHOOKER;
        _types |= HK_LIB_SUBSTRATE;
    }

    if(libellekit_handle && libellekit_handle == substrate_handle) {
        _MSHookMessageEx = NULL;
        _MSHookFunction = NULL;
        _MSHookMemory = NULL;
        _MSGetImageByName = NULL;
        _MSCloseImage = NULL;
        _MSFindSymbol = NULL;
    }

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

            // resolve this in case it exists
            if(!_LBHookMessage) _LBHookMessage = dlsym(libhooker_handle, "LBHookMessage");
        }

        if(libblackjack_handle) {
            // resolve symbols
            if(!_LBHookMessage) _LBHookMessage = dlsym(libblackjack_handle, "LBHookMessage");
        }
    }

    if(_types & HK_LIB_SUBSTITUTE) {
        if(!substitute_handle) {
            substitute_path = ROOT_PATH_NS(@PATH_SUBSTITUTE);
            substitute_handle = dlopen([substitute_path fileSystemRepresentation], RTLD_LAZY);
        }

        if(!substitute_handle) {
            substitute_path = ROOT_PATH_NS(@PATH_SUBSTITUTE2);
            substitute_handle = dlopen([substitute_path fileSystemRepresentation], RTLD_LAZY);
        }

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
        if(!substrate_handle) {
            substrate_path = ROOT_PATH_NS(@PATH_SUBSTRATE);
            substrate_handle = dlopen([substrate_path fileSystemRepresentation], RTLD_LAZY);
        }

        if(!substrate_handle) {
            substrate_path = ROOT_PATH_NS(@PATH_SUBSTRATE2);
            substrate_handle = dlopen([substrate_path fileSystemRepresentation], RTLD_LAZY);
        }

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

    if(dlopen_preflight(ROOT_PATH_C(PATH_LIBHOOKER))) {
        result |= HK_LIB_LIBHOOKER;
    }

    if(dlopen_preflight(ROOT_PATH_C(PATH_SUBSTITUTE)) || dlopen_preflight(ROOT_PATH_C(PATH_SUBSTITUTE2))) {
        result |= HK_LIB_SUBSTITUTE;
    }

    if(dlopen_preflight(ROOT_PATH_C(PATH_SUBSTRATE)) || dlopen_preflight(ROOT_PATH_C(PATH_SUBSTRATE2))) {
        result |= HK_LIB_SUBSTRATE;
    }

    if(dlopen_preflight(ROOT_PATH_C(PATH_ELLEKIT))) {
        result |= HK_LIB_ELLEKIT;
    }

    #ifdef fishhook_h
    result |= HK_LIB_FISHHOOK;
    #endif

    #ifdef dobby_h
    result |= HK_LIB_DOBBY;
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
            @"path" : ROOT_PATH_NS(@PATH_LIBHOOKER)
        }];
    }

    if(types & HK_LIB_ELLEKIT) {
        [result addObject:@{
            @"id" : @"ellekit",
            @"name" : @"ElleKit",
            @"type" : [NSNumber numberWithUnsignedInt:HK_LIB_ELLEKIT],
            @"path" : ROOT_PATH_NS(@PATH_ELLEKIT)
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

    #ifdef dobby_h
    if(types & HK_LIB_DOBBY) {
        [result addObject:@{
            @"id" : @"dobby",
            @"name" : @"Dobby",
            @"type" : [NSNumber numberWithUnsignedInt:HK_LIB_DOBBY]
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
        defaultSubstitutor = [self new];
        // intentionally don't set types so it will only init what's currently loaded into the process
        [defaultSubstitutor initLibraries];
    });

    return defaultSubstitutor;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    hookkit_status_t result = HK_ERR;

    if(_types & HK_LIB_LIBHOOKER) {
        if(_LBHookMessage) {
            int lh_result = _LBHookMessage(objcClass, selector, replacement, old_ptr);

            if(lh_result == LIBHOOKER_OK) {
                return HK_OK;
            } else {
                // handle libhooker error codes
                lib_errno = lh_result;
                lib_errno_type = HK_LIB_LIBHOOKER;
                return result;
            }
        }
    }

    if(_types & HK_LIB_SUBSTITUTE) {
        if(_substitute_hook_objc_message) {
            int sub_result = _substitute_hook_objc_message(objcClass, selector, replacement, (void *)old_ptr, NULL);

            if(sub_result == SUBSTITUTE_OK) {
                return HK_OK;
            } else {
                // handle substitute error codes
                lib_errno = sub_result;
                lib_errno_type = HK_LIB_SUBSTITUTE;
                return result;
            }
        }
    }

    if(_MSHookMessageEx) {
        _MSHookMessageEx(objcClass, selector, replacement, (IMP *)old_ptr);
        return HK_OK;
    }

    // todo: maybe have native objc swizzling?

    if(result == HK_ERR) {
        result |= HK_ERR_NOT_SUPPORTED;
    }

    return result;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    if(_batching) {
        HKFunctionHook* hook = [HKFunctionHook new];
        [hook setFunction:[NSValue valueWithPointer:function]];
        [hook setReplacement:[NSValue valueWithPointer:replacement]];
        [hook setOrig:[NSValue valueWithPointer:old_ptr]];

        functionHooks = [functionHooks arrayByAddingObject:hook];
        return HK_OK;
    }

    hookkit_status_t result = HK_ERR;

    if(_types & HK_LIB_LIBHOOKER) {
        if(_LHHookFunctions) {
            struct LHFunctionHook hook = {
                function, replacement, (void *)old_ptr, NULL
            };

            int lh_result = _LHHookFunctions(&hook, 1);

            if(lh_result == 1) {
                return HK_OK;
            } else {
                // handle libhooker error codes
                lib_errno = lh_result;
                lib_errno_type = HK_LIB_LIBHOOKER;
                return result;
            }
        }
    }
    
    if(_types & HK_LIB_SUBSTITUTE) {
        if(_substitute_hook_functions) {
            struct substitute_function_hook hook = {
                function, replacement, (void *)old_ptr, 0
            };

            int sub_result = _substitute_hook_functions(&hook, 1, NULL, 0);

            if(sub_result == SUBSTITUTE_OK) {
                return HK_OK;
            } else {
                // handle substitute error codes
                lib_errno = sub_result;
                lib_errno_type = HK_LIB_SUBSTITUTE;
                return result;
            }
        }
    }
    
    #ifdef fishhook_h
    if(_types == HK_LIB_FISHHOOK) {
        Dl_info info;
        if(dladdr(function, &info)) {
            if(rebind_symbols((struct rebinding[1]){{info.dli_sname, replacement, old_ptr}}, 1)) {
                return HK_OK;
            }
        }
    }
    #endif

    #ifdef dobby_h
    if(_types == HK_LIB_DOBBY) {
        dobby_enable_near_branch_trampoline();
        DobbyHook(function, replacement, (dobby_dummy_func_t *)old_ptr);
        dobby_disable_near_branch_trampoline();
        return HK_OK;
    }
    #endif

    if(_MSHookFunction) {
        _MSHookFunction(function, replacement, old_ptr);
        return HK_OK;
    }

    if(result == HK_ERR) {
        result |= HK_ERR_NOT_SUPPORTED;
    }

    return result;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    if(_batching) {
        HKMemoryHook* hook = [HKMemoryHook new];
        [hook setTarget:[NSValue valueWithPointer:target]];
        [hook setData:[NSValue valueWithPointer:data]];
        [hook setSize:[NSNumber numberWithInt:size]];

        memoryHooks = [memoryHooks arrayByAddingObject:hook];
        return HK_OK;
    }

    hookkit_status_t result = HK_ERR;

    if(_types & HK_LIB_LIBHOOKER) {
        if(_LHPatchMemory) {
            struct LHMemoryPatch hook = {
                target, data, size, 0
            };

            int lh_result = _LHPatchMemory(&hook, 1);

            if(lh_result == 1) {
                return HK_OK;
            } else {
                // handle libhooker error codes
                lib_errno = lh_result;
                lib_errno_type = HK_LIB_LIBHOOKER;
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

    #ifdef dobby_h
    if(_types == HK_LIB_DOBBY) {
        MemoryOperationError dobby_result = DobbyCodePatch(target, (uint8_t *)data, size);

        if(dobby_result == kMemoryOperationSuccess) {
            return HK_OK;
        } else {
            lib_errno = dobby_result;
            lib_errno_type = HK_LIB_DOBBY;
            return result;
        }
    }
    #endif

    if(_MSHookMemory) {
        _MSHookMemory(target, data, size);
        return HK_OK;
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

    if(_MSGetImageByName) {
        return (HKImageRef)_MSGetImageByName([path fileSystemRepresentation]);
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
    
    if(_MSCloseImage) {
        _MSCloseImage((MSImageRef)image);
        return;
    }
}

- (hookkit_status_t)findSymbolsInImage:(HKImageRef)image symbolNames:(NSArray<NSString *> *)symbolNames outSymbols:(NSArray<NSValue *> **)outSymbols {
    hookkit_status_t result = HK_ERR;

    if(image != NULL) {
        // libhooker and substitute do not natively handle a NULL value (all images) for image. Keep that to substrate-only as a compatibility layer.

        if(_types & HK_LIB_LIBHOOKER) {
            if(_LHFindSymbols) {
                // todo
            }
        }
        
        if(_types & HK_LIB_SUBSTITUTE) {
            if(_substitute_find_private_syms) {
                // todo
            }
        }
    }
    
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

    if(result == HK_ERR) {
        result |= HK_ERR_NOT_SUPPORTED;
    }

    return result;
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    NSArray<NSValue *>* syms = nil;
    hookkit_status_t result = [self findSymbolsInImage:image symbolNames:@[symbolName] outSymbols:&syms];

    if(result == HK_OK) {
        return [syms[0] pointerValue];
    }
    
    return NULL;
}

- (hookkit_status_t)executeHooks {
    hookkit_status_t result = HK_ERR;

    BOOL didFunctions = ([functionHooks count] == 0);
    BOOL didMemory = ([memoryHooks count] == 0);

    if(!didFunctions && _types & HK_LIB_LIBHOOKER) {
        if(_LHHookFunctions) {
            NSMutableData* hooks = [NSMutableData new];

            for(HKFunctionHook* hkhook in functionHooks) {
                struct LHFunctionHook hook = {
                    [[hkhook function] pointerValue], [[hkhook replacement] pointerValue], [[hkhook orig] pointerValue], 0
                };

                [hooks appendBytes:&hook length:sizeof(struct LHFunctionHook)];
            }

            if(_LHHookFunctions([hooks mutableBytes], [functionHooks count])) {
                didFunctions = YES;
            }
        }
    }

    if(!didFunctions && _types & HK_LIB_SUBSTITUTE) {
        if(_substitute_hook_functions) {
            NSMutableData* hooks = [NSMutableData new];

            for(HKFunctionHook* hkhook in functionHooks) {
                struct substitute_function_hook hook = {
                    [[hkhook function] pointerValue], [[hkhook replacement] pointerValue], [[hkhook orig] pointerValue], 0
                };

                [hooks appendBytes:&hook length:sizeof(struct substitute_function_hook)];
            }

            _substitute_hook_functions([hooks mutableBytes], [functionHooks count], NULL, 0);
            didFunctions = YES;
        }
    }

    #ifdef fishhook_h
    if(!didFunctions && _types == HK_LIB_FISHHOOK) {
        NSMutableData* hooks = [NSMutableData new];

        for(HKFunctionHook* hkhook in functionHooks) {
            Dl_info info;
            if(dladdr([[hkhook function] pointerValue], &info)) {
                struct rebinding hook = {
                    info.dli_sname, [[hkhook replacement] pointerValue], [[hkhook orig] pointerValue]
                };

                [hooks appendBytes:&hook length:sizeof(struct rebinding)];
            }
        }

        rebind_symbols((struct rebinding *)[hooks bytes], [functionHooks count]);
        didFunctions = YES;
    }
    #endif

    #ifdef dobby_h
    if(!didFunctions && _types == HK_LIB_DOBBY) {
        dobby_enable_near_branch_trampoline();

        for(HKFunctionHook* hkhook in functionHooks) {
            DobbyHook([[hkhook function] pointerValue], [[hkhook replacement] pointerValue], (dobby_dummy_func_t *)[[hkhook orig] pointerValue]);
        }

        dobby_disable_near_branch_trampoline();

        didFunctions = YES;
    }
    #endif

    if(!didFunctions) {
        if(_MSHookFunction) {
            for(HKFunctionHook* hkhook in functionHooks) {
                _MSHookFunction([[hkhook function] pointerValue], [[hkhook replacement] pointerValue], [[hkhook orig] pointerValue]);
            }

            didFunctions = YES;
        }
    }

    if(!didMemory && _types & HK_LIB_LIBHOOKER) {
        if(_LHPatchMemory) {
            NSMutableData* hooks = [NSMutableData new];

            for(HKMemoryHook* hkhook in memoryHooks) {
                struct LHMemoryPatch hook = {
                    [[hkhook target] pointerValue], [[hkhook data] pointerValue], [[hkhook size] intValue], 0
                };

                [hooks appendBytes:&hook length:sizeof(struct LHMemoryPatch)];
            }

            if(_LHPatchMemory([hooks mutableBytes], [memoryHooks count])) {
                didMemory = YES;
            }
        }
    }

    if(!didMemory && _types & HK_LIB_SUBSTITUTE) {
        if(_SubHookMemory) {
            for(HKMemoryHook* hkhook in memoryHooks) {
                _SubHookMemory([[hkhook target] pointerValue], [[hkhook data] pointerValue], [[hkhook size] intValue]);
            }

            didMemory = YES;
        }
    }

    #ifdef dobby_h
    if(!didMemory && _types == HK_LIB_DOBBY) {
        for(HKMemoryHook* hkhook in memoryHooks) {
            DobbyCodePatch([[hkhook target] pointerValue], (uint8_t *)[[hkhook data] pointerValue], [[hkhook size] intValue]);
        }

        didMemory = YES;
    }
    #endif

    if(!didMemory) {
        if(_MSHookMemory) {
            for(HKMemoryHook* hkhook in memoryHooks) {
                _MSHookMemory([[hkhook target] pointerValue], [[hkhook data] pointerValue], [[hkhook size] intValue]);
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

- (int)getLibErrno:(hookkit_lib_t *)outType {
    if(outType) {
        *outType = lib_errno_type;
    }

    int result = lib_errno;

    // clear errno
    lib_errno = 0;
    lib_errno_type = HK_LIB_NONE;

    return result;
}
@end
