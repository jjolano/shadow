#ifndef shadow_ruleset_compiler_h
#define shadow_ruleset_compiler_h

#import <Foundation/Foundation.h>

@class RulesetEngine;
@class NSURL;

// Framework-internal: parse + validate + compile + persist pipeline for
// rulesets (Candidate 5). RulesetEngine exposes matching only; +load delegates
// here. Hidden visibility, not exported.
__attribute__((visibility("hidden")))
@interface ShadowRulesetCompiler : NSObject

// Full load path for one ruleset URL: v2 compiled cache (if the plist's
// mtime+size match), else parse + compile + persist; per-URL last-known-good
// on failure. Returns nil only when a ruleset never loaded successfully.
+ (RulesetEngine *)compileRulesetAtURL:(NSURL *)url;
@end
#endif