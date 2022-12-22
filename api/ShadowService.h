#import <Foundation/Foundation.h>
#import "common.h"

@interface ShadowService : NSObject
- (void)addRuleset:(NSDictionary *)ruleset;

- (void)startService;
- (void)connectService;
- (void)startLocalService;

- (NSDictionary *)sendIPC:(NSString *)messageName withArgs:(NSDictionary *)args;

- (NSString *)resolvePath:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path;
- (NSArray *)getURLSchemes;
- (NSDictionary *)getVersions;
@end
