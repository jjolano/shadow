#import "HKSubstrate.h"
#import "vendor/substrate/substrate.h"

@implementation HKSubstrate
- (BOOL)_hookClass:(Class)objcClass selector:(SEL)selector replacement:(void *)replacement orig:(void **)orig {
    MSHookMessageEx(objcClass, selector, (IMP)replacement, (IMP *)orig);
    return YES;
}

- (BOOL)_hookFunction:(void *)function replacement:(void *)replacement orig:(void **)orig {
    MSHookFunction(function, replacement, orig);
    return YES;
}

- (int)_hookFunctions:(NSArray<HookKitFunctionHook *> *)functions {
    return -1;
}

- (BOOL)_hookRegion:(void *)target data:(const void *)data size:(size_t)size {
    MSHookMemory(target, data, size);
    return YES;
}

- (int)_hookRegions:(NSArray<HookKitMemoryHook *> *)regions {
    return -1;
}

- (void *)_openImage:(const char *)path {
    return (void *)MSGetImageByName(path);
}

- (void)_closeImage:(void *)image {
    // for some reason this symbol doesn't actually exist
    // MSCloseImage((MSImageRef)image);
}

- (void *)_findSymbol:(const char *)symbol image:(void *)image {
    return MSFindSymbol((MSImageRef)image, symbol);
}
@end
