#import <Shadow/Core+Utilities.h>
#import <Shadow/Backend.h>
#import <Shadow/Ruleset.h>
#import "RulesetStore.h"


#import "../common.h"
#import <Shadow/JBPath.h>

// Candidate 5: Backend is now a thin evaluation adapter over the atomic
// ruleset store (RulesetStore.m). Load/reload/change-detection/generation all
// moved to the store; queries that need rulesets grab ONE immutable snapshot
// (rulesets + generation as a consistent pair) for the whole evaluation.
// The path evaluation below (compliance veto / whitelist / blacklist / parent
// recursion) is unchanged; step 3 moves it into RestrictionEngine.

@interface ShadowBackend () {
    ShadowRulesetStore* store;
}
@end

@implementation ShadowBackend

- (instancetype)init {
    if((self = [super init])) {
        store = [ShadowRulesetStore new];
    }

    return self;
}

// C0-5: current ruleset generation. Consumers (Core.m's bounded decision
// cache) use it to treat cached decisions as stale the moment a ruleset
// reloads, instead of waiting out the TTL.
- (NSUInteger)rulesetGeneration {
    return [store generation];
}

// 1s-gated change check + one immutable snapshot for the caller's whole
// evaluation: (rulesets, generation) pair that can never skew across a
// concurrent reload (replaces the old per-query @synchronized array grab).
- (ShadowRulesetSnapshot *)_currentSnapshot {
    [store checkForChanges];
    return [store currentSnapshot];
}

- (BOOL)isPathRestricted:(NSString *)path {
    if(!path || [path length] == 0 || [path isEqualToString:@"/"] || ![path isAbsolutePath]) {
        return NO;
    }

    [store checkForChanges];

    // One immutable snapshot for gen + rulesets (see _currentSnapshot).
    ShadowRulesetSnapshot* snapshot = [store currentSnapshot];
    NSUInteger gen = snapshot.generation;

    // Header types this cache as <NSString *, NSArray *>; entries are packed
    // NSNumbers, so cast (header is public and unchanged).
    NSNumber* cached = (NSNumber *)[cache_restricted objectForKey:path];

    if(cached) {
        // Packed as (generation << 1) | restricted: one NSNumber per entry
        // instead of a 2-element array, with identical generation invalidation.
        unsigned long long v = [cached unsignedLongLongValue];

        if((NSUInteger)(v >> 1) == gen) {
            return (v & 1) != 0;
        }
    }

    // pass 1: compliance (hard veto)
    for(RulesetEngine* ruleset in snapshot.rulesets) {
        if(![ruleset isPathCompliant:path]) {
            [cache_restricted setObject:(NSArray *)(id)@(((unsigned long long)gen << 1) | 1) forKey:path];
            return YES;
        }
    }

    // pass 2: whitelist
    BOOL whitelisted = NO;

    for(RulesetEngine* ruleset in snapshot.rulesets) {
        if([ruleset isPathWhitelisted:path]) {
            whitelisted = YES;
            break;
        }
    }

    // pass 3: blacklist
    BOOL blacklisted = NO;

    for(RulesetEngine* ruleset in snapshot.rulesets) {
        if([ruleset isPathBlacklisted:path]) {
            blacklisted = YES;
            break;
        }
    }

    BOOL restricted = blacklisted && !whitelisted;

    if(!restricted) {
        restricted = [self isPathRestricted:[path stringByDeletingLastPathComponent]];
    }

    [cache_restricted setObject:(NSArray *)(id)@(((unsigned long long)gen << 1) | (restricted ? 1 : 0)) forKey:path];
    return restricted;
}

- (BOOL)isSchemeRestricted:(NSString *)scheme {
    if(!scheme || [scheme length] == 0) {
        return NO;
    }

    // C0-3: compare case-insensitively — detectors probe case variants
    // ("Cydia", "SILEO") to dodge exact matches. Rulesets additionally
    // normalize their entries to lowercase at load (Ruleset.m _compile).
    NSString* scheme_lower = [scheme lowercaseString];

    // Add some exceptions (direct compares: no per-call array allocation).
    if([scheme_lower isEqualToString:@"file"] || [scheme_lower isEqualToString:@"http"] || [scheme_lower isEqualToString:@"https"]) {
        return NO;
    }

    BOOL restricted = NO;

    // Check rulesets against the immutable snapshot (the old direct `rulesets`
    // ivar iteration could UAF across a concurrent reload).
    for(RulesetEngine* ruleset in [self _currentSnapshot].rulesets) {
        if([ruleset isSchemeRestricted:scheme_lower]) {
            restricted = YES;
            break;
        }
    }

    return restricted;
}

// C0-3: ruleset-driven bundle-ID check (the static well-known list lives in
// -[Shadow isBundleIDRestricted:], which consults this for the user-extensible
// half). Rulesets normalize their entries to lowercase at load.
- (BOOL)isBundleIDRestricted:(NSString *)bundleID {
    if(!bundleID || [bundleID length] == 0) {
        return NO;
    }

    NSString* bundleID_lower = [bundleID lowercaseString];

    for(RulesetEngine* ruleset in [self _currentSnapshot].rulesets) {
        if([ruleset isBundleIDRestricted:bundleID_lower]) {
            return YES;
        }
    }

    return NO;
}
@end