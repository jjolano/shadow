#ifndef shadow_restriction_engine_h
#define shadow_restriction_engine_h

#import <Foundation/Foundation.h>
#import <Shadow/RestrictionQuery.h>

@class ShadowRulesetStore;

// Candidate 5 engine: evaluation + the single generation-aware decision cache.
// Hosts BOTH evaluators during the differential migration: the legacy engine
// (the pre-Candidate-5 pipeline, preserved verbatim) and the new resolver-
// based engine. -isPathRestrictedQuery: runs both and returns per the
// SHADOW_NEW_ENGINE_AUTHORITATIVE cutover flag (see RestrictionEngine.m).
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