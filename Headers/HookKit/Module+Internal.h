#ifndef hookkit_module_internal_h
#define hookkit_module_internal_h

#import <Foundation/Foundation.h>
#import <HookKit/Module.h>
#import <HookKit/Hook.h>

@interface HookKitModule (Internal)
- (BOOL)_hookClass:(Class)objcClass selector:(SEL)selector replacement:(void *)replacement orig:(void **)orig;
- (BOOL)_hookFunction:(void *)function replacement:(void *)replacement orig:(void **)orig;
- (int)_hookFunctions:(NSArray<HookKitFunctionHook *> *)functions;
- (BOOL)_hookRegion:(void *)target data:(const void *)data size:(size_t)size;
- (int)_hookRegions:(NSArray<HookKitMemoryHook *> *)regions;

- (void *)_openImage:(const char *)path;
- (void)_closeImage:(void *)image;

- (void *)_findSymbol:(const char *)symbol image:(void *)image;
@end
#endif
