#ifndef hookkit_hook_h
#define hookkit_hook_h

#import <Foundation/Foundation.h>

@interface HookKitHook : NSObject
@end

@interface HookKitClassHook : HookKitHook
@property (assign, nonatomic) Class objcClass;
@property (assign, nonatomic) SEL selector;
@property (assign, nonatomic) void* replacement;
@property (assign, nonatomic) void** orig;

+ (instancetype)hook:(Class)objcClass selector:(SEL)selector replacement:(void *)replacement orig:(void **)orig;
@end

@interface HookKitFunctionHook : HookKitHook
@property (assign, nonatomic) void* function;
@property (assign, nonatomic) void* replacement;
@property (assign, nonatomic) void** orig;

+ (instancetype)hook:(void *)function replacement:(void *)replacement orig:(void **)orig;
@end

@interface HookKitMemoryHook : HookKitHook
@property (assign, nonatomic) void* target;
@property (assign, nonatomic) const void* data;
@property (assign, nonatomic) size_t size;

+ (instancetype)hook:(void *)target data:(const void *)data size:(size_t)size;
@end

#endif
