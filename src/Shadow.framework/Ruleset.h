#ifndef shadow_ruleset_h
#define shadow_ruleset_h

#import <Foundation/Foundation.h>

FOUNDATION_EXPORT NSString* const kShadowRulesetCacheSuffix;

__attribute__((visibility("hidden")))
@interface RulesetEngine : NSObject

@property (copy, nonatomic, readonly) NSDictionary* payloadDictionary;

+ (instancetype)rulesetWithURL:(NSURL *)url;

- (BOOL)isPathCompliant:(NSString *)path;
- (BOOL)isPathWhitelisted:(NSString *)path;
- (BOOL)isPathBlacklisted:(NSString *)path;
- (BOOL)isSchemeRestricted:(NSString *)scheme;
- (BOOL)isBundleIDRestricted:(NSString *)bundleID;
@end

#endif
