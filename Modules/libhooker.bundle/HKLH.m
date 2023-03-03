#import "HKLH.h"
#import "vendor/libhooker/libhooker.h"
#import "vendor/libhooker/libblackjack.h"

@implementation HKLH
- (BOOL)_hookClass:(Class)objcClass selector:(SEL)selector replacement:(void *)replacement orig:(void **)orig {
    return LBHookMessage(objcClass, selector, replacement, orig) == LIBHOOKER_OK;
}

- (BOOL)_hookFunction:(void *)function replacement:(void *)replacement orig:(void **)orig {
    struct LHFunctionHook hook = {
        function, replacement, (void *)orig, NULL
    };

    return LHHookFunctions(&hook, 1) == 1;
}

- (int)_hookFunctions:(NSArray<HookKitFunctionHook *> *)functions {
    NSMutableData* hooks = [NSMutableData new];

    for(HookKitFunctionHook* function in functions) {
        struct LHFunctionHook hook = {
            [function function], [function replacement], [function orig], NULL
        };

        [hooks appendBytes:&hook length:sizeof(struct LHFunctionHook)];
    }

    int result = LHHookFunctions([hooks mutableBytes], [functions count]);

    if(result < [functions count]) {
        NSLog(@"[HKLH] warning: batch LHHookFunctions retval less than expected (%d/%lu)", result, [functions count]);
    }

    return result;
}

- (BOOL)_hookRegion:(void *)target data:(const void *)data size:(size_t)size {
    struct LHMemoryPatch hook = {
        target, data, size, 0
    };

    return LHPatchMemory(&hook, 1) == 1;
}

- (int)_hookRegions:(NSArray<HookKitMemoryHook *> *)regions {
    NSMutableData* hooks = [NSMutableData new];

    for(HookKitMemoryHook* region in regions) {
        struct LHMemoryPatch hook = {
            [region target], [region data], [region size], 0
        };

        [hooks appendBytes:&hook length:sizeof(struct LHMemoryPatch)];
    }

    int result = LHPatchMemory([hooks mutableBytes], [regions count]);

    if(result < [regions count]) {
        NSLog(@"[HKLH] warning: batch LHPatchMemory retval less than expected (%d/%lu)", result, [regions count]);
    }

    return result;
}

- (void *)_openImage:(const char *)path {
    return (void *)LHOpenImage(path);
}

- (void)_closeImage:(void *)image {
    LHCloseImage((struct libhooker_image *)image);
}

- (void *)_findSymbol:(const char *)symbol image:(void *)image {
    void* result = NULL;

    if(LHFindSymbols((struct libhooker_image *)image, &symbol, &result, 1)) {
        return result;
    }

    return NULL;
}
@end
