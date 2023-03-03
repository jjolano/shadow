#import "HKDobby.h"
#import "vendor/dobby/dobby.h"

@implementation HKDobby
// - (BOOL)_hookClass:(Class)objcClass selector:(SEL)selector replacement:(void *)replacement orig:(void **)orig {
//     return NO;
// }

- (BOOL)_hookFunction:(void *)function replacement:(void *)replacement orig:(void **)orig {
    dobby_enable_near_branch_trampoline();
    BOOL result = DobbyHook(function, replacement, (dobby_dummy_func_t *)orig);
    dobby_disable_near_branch_trampoline();

    return result;
}

- (int)_hookFunctions:(NSArray<HookKitFunctionHook *> *)functions {
    return -1;
}

- (BOOL)_hookRegion:(void *)target data:(const void *)data size:(size_t)size {
    return DobbyCodePatch(target, (uint8_t *)data, size) == kMemoryOperationSuccess;
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
