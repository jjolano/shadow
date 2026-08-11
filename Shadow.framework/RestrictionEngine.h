#ifndef shadow_restriction_engine_h
#define shadow_restriction_engine_h

#import <Foundation/Foundation.h>
#import <Shadow/RestrictionQuery.h>

@class ShadowRulesetStore;

// Candidate 5 engine: evaluation + the single generation-aware decision cache.
// The resolver-based engine (RestrictionResolver.m) is THE path engine — the
// Candidate 5 differential (dual legacy/resolver evaluation) was removed once
// parity held; see RestrictionEngine.m.
// Framework-internal (hidden visibility, not exported).
__attribute__((visibility("hidden")))
@interface ShadowRestrictionEngine : NSObject

- (instancetype)initWithStore:(ShadowRulesetStore *)store;

- (BOOL)isPathRestrictedQuery:(ShadowRestrictionQuery *)query;

// Compatibility entry for absolute-path queries (the public
// -[ShadowBackend isPathRestricted:] adapter routes here).
- (BOOL)isPathRestricted:(NSString *)path;

// Served directly from the atomic store snapshot (cutover done for these:
// identical ruleset objects + identical matching methods + identical
// normalization; the snapshot only makes the iteration concurrency-safe).
- (BOOL)isSchemeRestricted:(NSString *)scheme;
- (BOOL)isBundleIDRestricted:(NSString *)bundleID;

- (NSUInteger)rulesetGeneration;
@end
#endif