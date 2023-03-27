#import "HKDobby.h"
#import "vendor/dobby/dobby.h"

@implementation HKDobby
// - (BOOL)_hookClass:(Class)objcClass selector:(SEL)selector replacement:(void *)replacement orig:(void **)orig {
//     return NO;
// }

- (BOOL)_hookFunction:(void *)function replacement:(void *)replacement orig:(void **)orig {
    dobby_enable_near_branch_trampoline();
    int result = DobbyHook(function, replacement, (dobby_dummy_func_t *)orig);
    dobby_disable_near_branch_trampoline();

    return result == 0;
}

- (int)_hookFunctions:(NSArray<HookKitFunctionHook *> *)functions {
    int result = 0;

    dobby_enable_near_branch_trampoline();

    for(HookKitFunctionHook* function in functions) {
        if(DobbyHook([function function], [function replacement], (dobby_dummy_func_t *)[function orig]) == 0) {
            result += 1;
        }
    }
    
    dobby_disable_near_branch_trampoline();
    return result;
}

- (BOOL)_hookRegion:(void *)target data:(const void *)data size:(size_t)size {
    return DobbyCodePatch(target, (uint8_t *)data, size) == 0;
}

- (int)_hookRegions:(NSArray<HookKitMemoryHook *> *)regions {
    return -1;
}

// - (void *)_openImage:(const char *)path {
//     return (void *)MSGetImageByName(path);
// }

// - (void)_closeImage:(void *)image {
//     MSCloseImage((MSImageRef)image);
// }

// - (void *)_findSymbol:(const char *)symbol image:(void *)image {
//     return MSFindSymbol((MSImageRef)image, symbol);
// }
@end
