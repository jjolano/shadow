#import <HookKit/Compat.h>
#import <HookKit/Core.h>
#import <HookKit/Hook.h>
#import <HookKit/Module.h>

@implementation HKSubstitutor {
    NSMutableArray<__kindof HookKitHook *>* batchHooks;
    __kindof HookKitModule* module;
}

@synthesize types, batching;

- (instancetype)init {
    if((self = [super init])) {
        batchHooks = [NSMutableArray new];
        module = nil;
        types = 0;
    }

    return self;
}

- (void)initLibraries {
    HookKitCore* core = [HookKitCore sharedInstance];
    module = [core defaultModule];

    if(types != 0) {
        NSArray* typeinfo = [[self class] getSubstitutorTypeInfo:types];

        if([typeinfo count]) {
            module = [core getModuleWithIdentifier:[typeinfo[0] objectForKey:@"id"]];
        }
    }
}

+ (hookkit_lib_t)getAvailableSubstitutorTypes {
    hookkit_lib_t types = 0;

    HookKitCore* core = [HookKitCore sharedInstance];
    hookkit_lib_t type = 1;

    NSArray* module_infos = [core getModuleInfo];

    for(__unused NSDictionary* module_info in module_infos) {
        types |= type;
        type = type * 2;
    }

    return types;
}

+ (NSArray<NSDictionary *> *)getSubstitutorTypeInfo:(hookkit_lib_t)types {
    NSMutableArray* result = [NSMutableArray new];

    HookKitCore* core = [HookKitCore sharedInstance];
    hookkit_lib_t type = 1;

    NSArray* module_infos = [core getModuleInfo];

    for(NSDictionary* module_info in module_infos) {
        if((types & type) == type) {
            [result addObject:@{
                @"id" : module_info[@"Identifier"],
                @"name" : module_info[@"Description"],
                @"type" : @(type)
            }];
        }

        type = type * 2;
    }

    return [result copy];
}

+ (instancetype)substitutorWithTypes:(hookkit_lib_t)types {
    HKSubstitutor* substitutor = [self new];
    [substitutor setTypes:types];
    [substitutor initLibraries];
    return substitutor;
}

+ (instancetype)defaultSubstitutor {
    static HKSubstitutor* defaultSubstitutor = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        defaultSubstitutor = [self new];
        [defaultSubstitutor initLibraries];
    });

    return defaultSubstitutor;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    HookKitClassHook* hook = [HookKitClassHook hook:objcClass selector:selector replacement:replacement orig:old_ptr];

    if(batching) {
        [batchHooks addObject:hook];
        return HK_OK;
    }

    return [module executeHook:hook] ? HK_OK : HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    HookKitFunctionHook* hook = [HookKitFunctionHook hook:function replacement:replacement orig:old_ptr];

    if(batching) {
        [batchHooks addObject:hook];
        return HK_OK;
    }

    return [module executeHook:hook] ? HK_OK : HK_ERR_NOT_SUPPORTED;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    HookKitMemoryHook* hook = [HookKitMemoryHook hook:target data:data size:size];

    if(batching) {
        [batchHooks addObject:hook];
        return HK_OK;
    }

    return [module executeHook:hook] ? HK_OK : HK_ERR_NOT_SUPPORTED;
}

- (HKImageRef)openImage:(NSString *)path {
    return (HKImageRef)[module openImageWithPath:path];
}

- (void)closeImage:(HKImageRef)image {
    [module closeImage:(hookkit_image_t)image];
}

- (hookkit_status_t)findSymbolsInImage:(HKImageRef)image symbolNames:(NSArray<NSString *> *)symbolNames outSymbols:(NSArray<NSValue *> **)outSymbols {
    NSMutableArray* outSyms = [NSMutableArray new];

    for(NSString* symbolName in symbolNames) {
        [outSyms addObject:[NSValue valueWithPointer:[self findSymbolInImage:image symbolName:symbolName]]];
    }

    *outSymbols = [outSyms copy];
    return HK_OK;
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    return [module findSymbolName:symbolName inImage:(hookkit_image_t)image];
}

- (hookkit_status_t)executeHooks {
    int result = [module executeHooks:batchHooks];
    [batchHooks removeAllObjects];

    return result ? HK_OK : HK_ERR;
}

- (int)getLibErrno:(hookkit_lib_t *)outType {
    return 0;
}
@end
