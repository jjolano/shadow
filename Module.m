#import <HookKit/Module.h>
#import <HookKit/Hook.h>
#import <HookKit/Module+Internal.h>

#import <mach-o/dyld.h>

@implementation HookKitModule
@synthesize functionHookBatchingSupported, memoryHookBatchingSupported, nullImageSearchSupported;

- (BOOL)executeHook:(__kindof HookKitHook *)hook {
    if([hook isKindOfClass:[HookKitClassHook class]]) {
        HookKitClassHook* classHook = (HookKitClassHook *)hook;
        return [self _hookClass:[classHook objcClass] selector:[classHook selector] replacement:[classHook replacement] orig:[classHook orig]];
    }

    if([hook isKindOfClass:[HookKitFunctionHook class]]) {
        HookKitFunctionHook* functionHook = (HookKitFunctionHook *)hook;
        return [self _hookFunction:[functionHook function] replacement:[functionHook replacement] orig:[functionHook orig]];
    }

    if([hook isKindOfClass:[HookKitMemoryHook class]]) {
        HookKitMemoryHook* memoryHook = (HookKitMemoryHook *)hook;
        return [self _hookRegion:[memoryHook target] data:[memoryHook data] size:[memoryHook size]];
    }

    return NO;
}

- (int)executeHooks:(NSArray<__kindof HookKitHook *> *)hooks {
    int result = 0;

    NSMutableArray<HookKitFunctionHook *>* functionHooks = [NSMutableArray new];
    NSMutableArray<HookKitMemoryHook *>* memoryHooks = [NSMutableArray new];

    for(__kindof HookKitHook* hook in hooks) {
        if([hook isKindOfClass:[HookKitClassHook class]]) {
            if([self executeHook:hook]) {
                result += 1;
            }

            continue;
        }

        if([hook isKindOfClass:[HookKitFunctionHook class]]) {
            if([self functionHookBatchingSupported]) {
                [functionHooks addObject:(HookKitFunctionHook *)hook];
            } else {
                if([self executeHook:hook]) {
                    result += 1;
                }
            }

            continue;
        }

        if([hook isKindOfClass:[HookKitMemoryHook class]]) {
            if([self memoryHookBatchingSupported]) {
                [memoryHooks addObject:(HookKitMemoryHook *)hook];
            } else {
                if([self executeHook:hook]) {
                    result += 1;
                }
            }
            
            continue;
        }
    }

    int function_batch_result = [self _hookFunctions:functionHooks];

    if(function_batch_result == -1) {
        // batching not supported, do one at a time
        for(HookKitFunctionHook* functionHook in functionHooks) {
            if([self executeHook:functionHook]) {
                result += 1;
            }
        }
    } else {
        result += function_batch_result;
    }

    int memory_batch_result = [self _hookRegions:memoryHooks];

    if(memory_batch_result == -1) {
        // batching not supported, do one at a time
        for(HookKitMemoryHook* memoryHook in memoryHooks) {
            if([self executeHook:memoryHook]) {
                result += 1;
            }
        }
    } else {
        result += memory_batch_result;
    }
    
    return result;
}

- (hookkit_image_t)openImageWithURL:(NSURL *)url {
    return (hookkit_image_t)[self _openImage:[[url path] fileSystemRepresentation]];
}

- (hookkit_image_t)openImageWithPath:(NSString *)path {
    NSURL* file_url = [NSURL fileURLWithPath:path isDirectory:NO];
    return [self openImageWithURL:file_url];
}

- (void)closeImage:(hookkit_image_t)image {
    if(image) {
        [self _closeImage:(void *)image];
    }
}

- (void *)findSymbolName:(NSString *)name {
    return [self findSymbolName:name inImage:NULL];
}

- (void *)findSymbolName:(NSString *)name inImage:(hookkit_image_t)image {
    if([self nullImageSearchSupported] || image) {
        return [self _findSymbol:[name UTF8String] image:(void *)image];
    }

    // iterate through all loaded dyld images and call findSymbol
    int count = _dyld_image_count();

    for(int i = 0; i < count; i++) {
        const char* image_name = _dyld_get_image_name(i);

        if(image_name) {
            void* _image = [self _openImage:image_name];
            void* symbol = [self _findSymbol:[name UTF8String] image:_image];
            [self _closeImage:_image];

            if(symbol) {
                NSLog(@"[HookKit] found symbol %@ in image %s", name, image_name);
                return symbol;
            }
        }
    }

    return NULL;
}
@end
