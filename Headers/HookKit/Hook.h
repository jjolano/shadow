#ifndef hookkit_hook_h
#define hookkit_hook_h

#import <Foundation/Foundation.h>

@interface HookKitHook : NSObject
@end

@interface HookKitClassHook : HookKitHook
@property (nonatomic) Class objcClass;
@property (nonatomic) SEL selector;
@property (nonatomic) void* replacement;
@property (nonatomic) void** orig;

+ (instancetype)hook:(Class)objcClass selector:(SEL)selector replacement:(void *)replacement orig:(void **)orig;
@end

@interface HookKitFunctionHook : HookKitHook
@property (nonatomic) void* function;
@property (nonatomic) void* replacement;
@property (nonatomic) void** orig;

+ (instancetype)hook:(void *)function replacement:(void *)replacement orig:(void **)orig;
@end

@interface HookKitMemoryHook : HookKitHook
@property (nonatomic) void* target;
@property (nonatomic) const void* data;
@property (nonatomic) size_t size;

+ (instancetype)hook:(void *)target data:(const void *)data size:(size_t)size;
@end

#endif
