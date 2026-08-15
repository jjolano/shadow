#ifndef system_rules_generator_h
#define system_rules_generator_h

#import <Foundation/Foundation.h>

__attribute__((visibility("default")))
@interface SystemRulesGenerator : NSObject
+ (NSInteger)writeDpkgRuleset;
@end

@interface SystemRulesGenerator (SystemRules)
// 1 = regenerated/written, 0 = skipped (up to date), -1 = failure.
+ (NSInteger)writeSystemRuleset;
// 1 = regenerated/written, 0 = skipped (content unchanged), -1 = failure.
+ (NSInteger)writeInstalledAppsRuleset;
@end
#endif
