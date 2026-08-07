// Harness-only RootBridge extensions (implemented in RootBridgeStub.m).

#import <RootBridge.h>

NS_ASSUME_NONNULL_BEGIN

@interface RootBridge (Harness)

// jbPath: fixture jbroot directory, or nil for rooted mode.
// rulesetsDir: staged rulesets directory (both modes).
+ (void)shdwHarnessSetJBPath:(nullable NSString*)jbPath rulesetsDir:(NSString*)rulesetsDir;

@end

NS_ASSUME_NONNULL_END
