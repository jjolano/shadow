#import <HookKit/Core.h>
#import <HookKit/Module+Internal.h>

@implementation HookKitModule (Internal)
- (BOOL)_hookClass:(Class)objcClass selector:(SEL)selector replacement:(void *)replacement orig:(void **)orig {
    HookKitModule* module = [[HookKitCore sharedInstance] defaultModule];

    if(module && module != self) {
        return [module _hookClass:objcClass selector:selector replacement:replacement orig:orig];
    }

    return NO;
}

- (BOOL)_hookFunction:(void *)function replacement:(void *)replacement orig:(void **)orig {
    HookKitModule* module = [[HookKitCore sharedInstance] defaultModule];

    if(module && module != self) {
        return [module _hookFunction:function replacement:replacement orig:orig];
    }

    return NO;
}

- (int)_hookFunctions:(NSArray<HookKitFunctionHook *> *)functions {
    HookKitModule* module = [[HookKitCore sharedInstance] defaultModule];

    if(module && module != self) {
        return [module _hookFunctions:functions];
    }

    return -1;
}

- (BOOL)_hookRegion:(void *)target data:(const void *)data size:(size_t)size {
    HookKitModule* module = [[HookKitCore sharedInstance] defaultModule];

    if(module && module != self) {
        return [module _hookRegion:target data:data size:size];
    }

    return NO;
}

- (int)_hookRegions:(NSArray<HookKitMemoryHook *> *)regions {
    HookKitModule* module = [[HookKitCore sharedInstance] defaultModule];

    if(module && module != self) {
        return [module _hookRegions:regions];
    }

    return -1;
}

- (void *)_openImage:(const char *)path {
    HookKitModule* module = [[HookKitCore sharedInstance] defaultModule];

    if(module && module != self) {
        return [module _openImage:path];
    }

    return NULL;
}

- (void)_closeImage:(void *)image {
    HookKitModule* module = [[HookKitCore sharedInstance] defaultModule];

    if(module && module != self) {
        return [module _closeImage:image];
    }
}

- (void *)_findSymbol:(const char *)symbol image:(void *)image {
    HookKitModule* module = [[HookKitCore sharedInstance] defaultModule];

    if(module && module != self) {
        return [module _findSymbol:symbol image:image];
    }

    return NULL;
}
@end
