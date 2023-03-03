#import "HKFH.h"
#import "vendor/fishhook/fishhook.h"

#import <dlfcn.h>

@implementation HKFH
// - (BOOL)_hookClass:(Class)objcClass selector:(SEL)selector replacement:(void *)replacement orig:(void **)orig {
//     return NO;
// }

- (BOOL)_hookFunction:(void *)function replacement:(void *)replacement orig:(void **)orig {
    Dl_info info;
    if(dladdr(function, &info)) {
        if(rebind_symbols((struct rebinding[1]){{info.dli_sname, replacement, orig}}, 1)) {
            return YES;
        }
    }

    return NO;
}

- (int)_hookFunctions:(NSArray<HookKitFunctionHook *> *)functions {
    NSMutableData* hooks = [NSMutableData new];

    for(HookKitFunctionHook* function in functions) {
        Dl_info info;
        if(dladdr([function function], &info)) {
            struct rebinding hook = {
                info.dli_sname, [function replacement], [function orig]
            };

            [hooks appendBytes:&hook length:sizeof(struct rebinding)];
        }
    }

    rebind_symbols((struct rebinding *)[hooks bytes], [functions count]);
    return [functions count];
}

// - (BOOL)_hookRegion:(void *)target data:(const void *)data size:(size_t)size {
//     return NO;
// }

// - (int)_hookRegions:(NSArray<HookKitMemoryHook *> *)regions {
//     return -1;
// }

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
