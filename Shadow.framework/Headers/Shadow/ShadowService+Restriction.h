#import <Foundation/Foundation.h>
#import "ShadowService.h"

@interface ShadowService (Restriction)
+ (BOOL)isPathCompliant:(NSString *)path withRuleset:(NSDictionary *)ruleset;
+ (BOOL)isPathWhitelisted:(NSString *)path withRuleset:(NSDictionary *)ruleset;
+ (BOOL)isPathBlacklisted:(NSString *)path withRuleset:(NSDictionary *)ruleset;
@end
