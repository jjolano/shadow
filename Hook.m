#import <HookKit/Hook.h>

@implementation HookKitHook
@end

@implementation HookKitClassHook
@synthesize objcClass, selector, replacement, orig;

+ (instancetype)hook:(Class)objcClass selector:(SEL)selector replacement:(void *)replacement orig:(void **)orig {
    HookKitClassHook* hook = [HookKitClassHook new];

    [hook setObjcClass:objcClass];
    [hook setSelector:selector];
    [hook setReplacement:replacement];
    [hook setOrig:orig];

    return hook;
}
@end

@implementation HookKitFunctionHook
@synthesize function, replacement, orig;

+ (instancetype)hook:(void *)function replacement:(void *)replacement orig:(void **)orig {
    HookKitFunctionHook* hook = [HookKitFunctionHook new];

    [hook setFunction:function];
    [hook setReplacement:replacement];
    [hook setOrig:orig];

    return hook;
}
@end

@implementation HookKitMemoryHook
@synthesize target, data, size;

+ (instancetype)hook:(void *)target data:(const void *)data size:(size_t)size {
    HookKitMemoryHook* hook = [HookKitMemoryHook new];
    
    [hook setTarget:target];
    [hook setData:data];
    [hook setSize:size];

    return hook;
}
@end
