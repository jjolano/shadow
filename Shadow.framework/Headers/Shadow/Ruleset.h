#ifndef shadow_ruleset_h
#define shadow_ruleset_h

#import <Foundation/Foundation.h>

@interface ShadowRuleset : NSObject {
    NSSet<NSString *>* set_urlschemes;
    NSSet<NSString *>* set_whitelist;
    NSSet<NSString *>* set_blacklist;

    NSPredicate* pred_whitelist;
    NSPredicate* pred_blacklist;
}

@property (strong, nonatomic) NSDictionary* internalDictionary;

+ (instancetype)rulesetWithURL:(NSURL *)url;
+ (instancetype)rulesetWithPath:(NSString *)path;

- (BOOL)isPathCompliant:(NSString *)path;
- (BOOL)isPathWhitelisted:(NSString *)path;
- (BOOL)isPathBlacklisted:(NSString *)path;
- (BOOL)isSchemeRestricted:(NSString *)scheme;
@end
#endif
