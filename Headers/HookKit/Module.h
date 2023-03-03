#ifndef hookkit_module_h
#define hookkit_module_h

#import <Foundation/Foundation.h>
#import <HookKit/Hook.h>

typedef const struct HKImage* hookkit_image_t;

@interface HookKitModule : NSObject
@property (nonatomic) BOOL functionHookBatchingSupported;
@property (nonatomic) BOOL memoryHookBatchingSupported;
@property (nonatomic) BOOL nullImageSearchSupported;

- (BOOL)executeHook:(id)hook;
- (int)executeHooks:(NSArray<__kindof HookKitHook *> *)hooks;

- (hookkit_image_t)openImageWithURL:(NSURL *)url;
- (hookkit_image_t)openImageWithPath:(NSString *)path;
- (void)closeImage:(hookkit_image_t)image;

- (void *)findSymbolName:(NSString *)name;
- (void *)findSymbolName:(NSString *)name inImage:(hookkit_image_t)image;
@end
#endif
