#ifndef shadow_ruleset_h
#define shadow_ruleset_h

#import <Foundation/Foundation.h>

// Suffix of the compiled-ruleset cache files RulesetEngine writes next to
// each ruleset plist (e.g. SystemRules.plist.shadowcache). Consumers that
// enumerate the rulesets directory (ShadowBackend) skip these files.
FOUNDATION_EXPORT NSString* const kShadowRulesetCacheSuffix;

// Candidate 5: RulesetEngine retains matching only. Parsing, validation,
// compilation and the compiled-cache persistence moved to RulesetCompiler.m
// (ShadowRulesetCompiler, framework-internal); loading via rulesetWithURL:
// delegates to it, preserving last-known-good per URL.
__attribute__((visibility("default")))
@interface RulesetEngine : NSObject

@property (strong, nonatomic) NSDictionary* payloadDictionary;

+ (instancetype)rulesetWithURL:(NSURL *)url;

- (BOOL)isPathCompliant:(NSString *)path;
- (BOOL)isPathWhitelisted:(NSString *)path;
- (BOOL)isPathBlacklisted:(NSString *)path;
- (BOOL)isSchemeRestricted:(NSString *)scheme;
- (BOOL)isBundleIDRestricted:(NSString *)bundleID;
@end
#endif