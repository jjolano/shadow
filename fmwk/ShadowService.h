#import <Foundation/Foundation.h>

@interface ShadowService : NSObject
- (void)startService;
- (void)connectService;

- (void)addRuleset:(NSDictionary *)ruleset;
- (void)loadRulesets;

- (NSDictionary *)sendIPC:(NSString *)messageName withArgs:(NSDictionary *)args;

- (NSString *)resolvePath:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isURLSchemeRestricted:(NSString *)scheme;
- (NSDictionary *)getVersions;
@end
