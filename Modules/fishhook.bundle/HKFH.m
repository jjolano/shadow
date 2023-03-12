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
        return rebind_symbols((struct rebinding[1]){{info.dli_sname, replacement, orig}}, 1) == 0;
    } else {
        // private symbol?
        return [super _hookFunction:function replacement:replacement orig:orig];
    }

    return NO;
}

- (int)_hookFunctions:(NSArray<HookKitFunctionHook *> *)functions {
    NSMutableData* hooks = [NSMutableData new];
    int priv_count = 0;

    for(HookKitFunctionHook* function in functions) {
        Dl_info info;
        if(dladdr([function function], &info)) {
            struct rebinding hook = {
                info.dli_sname, [function replacement], [function orig]
            };

            [hooks appendBytes:&hook length:sizeof(struct rebinding)];
        } else {
            // private symbol?
            if([super _hookFunction:[function function] replacement:[function replacement] orig:[function orig]]) {
                priv_count += 1;
            }
        }
    }

    rebind_symbols((struct rebinding *)[hooks mutableBytes], [functions count]);
    return [functions count] + priv_count;
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
