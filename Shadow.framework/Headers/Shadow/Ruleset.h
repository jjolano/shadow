#ifndef shadow_ruleset_h
#define shadow_ruleset_h

#import <Foundation/Foundation.h>

@interface ShadowRuleset : NSObject
@property (nonatomic) NSDictionary* internalDictionary;

+ (instancetype)rulesetWithURL:(NSURL *)url;
+ (instancetype)rulesetWithPath:(NSString *)path;

- (BOOL)isPathCompliant:(NSString *)path;
- (BOOL)isPathWhitelisted:(NSString *)path;
- (BOOL)isPathBlacklisted:(NSString *)path;
- (BOOL)isURLSchemeRestricted:(NSString *)scheme;
@end
#endif
