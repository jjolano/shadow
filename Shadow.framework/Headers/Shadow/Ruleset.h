#ifndef shadow_ruleset_h
#define shadow_ruleset_h

#import <Foundation/Foundation.h>

// Suffix of the compiled-ruleset cache files RulesetEngine writes next to
// each ruleset plist (e.g. SystemRules.plist.shadowcache). Consumers that
// enumerate the rulesets directory (ShadowBackend) skip these files.
FOUNDATION_EXPORT NSString* const kShadowRulesetCacheSuffix;

__attribute__((visibility("default")))
@interface RulesetEngine : NSObject {
    NSSet<NSString *>* set_urlschemes;
    NSSet<NSString *>* set_whitelist;
    NSSet<NSString *>* set_blacklist;

    NSPredicate* pred_whitelist;
    NSPredicate* pred_blacklist;
}

@property (strong, nonatomic) NSDictionary* payloadDictionary;

+ (instancetype)rulesetWithURL:(NSURL *)url;

- (BOOL)isPathCompliant:(NSString *)path;
- (BOOL)isPathWhitelisted:(NSString *)path;
- (BOOL)isPathBlacklisted:(NSString *)path;
- (BOOL)isSchemeRestricted:(NSString *)scheme;
- (BOOL)isBundleIDRestricted:(NSString *)bundleID;
@end
#endif
