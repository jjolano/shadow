#ifndef hookkit_core_h
#define hookkit_core_h

#import <Foundation/Foundation.h>
#import <HookKit/Module.h>

@interface HookKitCore : NSObject
+ (instancetype)sharedInstance;
- (__kindof HookKitModule *)defaultModule;

- (NSArray<NSDictionary *> *)getModuleInfo;
- (NSDictionary *)getModuleInfoWithIdentifier:(NSString *)identifier;

- (__kindof HookKitModule *)getModuleWithIdentifier:(NSString *)identifier;

- (void)registerModule:(__kindof HookKitModule *)module withIdentifier:(NSString *)identifier;
@end
#endif
