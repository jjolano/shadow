#ifndef shadow_ruleset_store_h
#define shadow_ruleset_store_h

#import <Foundation/Foundation.h>

@class RulesetEngine;

// Immutable rules snapshot: the ruleset array plus the generation it was
// built under. A snapshot is never mutated; a reload publishes a new one, so
// every reader sees a consistent (rulesets, generation) pair for the whole
// evaluation. Framework-internal (hidden visibility, not exported).
__attribute__((visibility("hidden")))
@interface ShadowRulesetSnapshot : NSObject {
    NSArray<RulesetEngine *>* _rulesets;
    NSUInteger _generation;
}

@property (nonatomic, readonly) NSArray<RulesetEngine *>* rulesets;
@property (nonatomic, readonly) NSUInteger generation;

+ (instancetype)snapshotWithRulesets:(NSArray<RulesetEngine *>*)rulesets generation:(NSUInteger)generation;
@end

// Atomic ruleset store: owns scanning JBPath(@SHADOW_RULESETS),
// the 1s change gate, reloads and the generation counter, and serves one
// immutable snapshot for path, scheme and bundle-ID queries. Last-known-good
// at snapshot level: a reload that yields no rulesets while a previous
// non-empty snapshot exists keeps the previous snapshot. Replaces the
// Framework-internal.
__attribute__((visibility("hidden")))
@interface ShadowRulesetStore : NSObject

// Current immutable snapshot (atomic; valid until the next reload).
- (ShadowRulesetSnapshot *)currentSnapshot;

// 1s-gated rulesets-dir scan; reloads when the dir or any ruleset file
// changed. Called per query (cheap: the gate makes it a load+compare).
- (void)checkForChanges;

- (NSUInteger)generation;
@end
#endif
