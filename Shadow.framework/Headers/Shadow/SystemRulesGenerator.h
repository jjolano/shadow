#ifndef system_rules_generator_h
#define system_rules_generator_h

#import <Foundation/Foundation.h>

__attribute__((visibility("default")))
@interface SystemRulesGenerator : NSObject
+ (NSDictionary *)generateSystemRuleset;
+ (BOOL)writeSystemRuleset;
@end
#endif
