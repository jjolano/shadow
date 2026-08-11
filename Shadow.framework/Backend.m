#import <Shadow/Core+Utilities.h>
#import <Shadow/Backend.h>
#import <Shadow/Ruleset.h>
#import "RulesetStore.h"
#import "RestrictionEngine.h"


#import "../common.h"
#import <Shadow/JBPath.h>

// Candidate 5: Backend.m is a compatibility adapter. The load/reload/
// change-detection/generation machinery moved to the ruleset store
// (RulesetStore.m); path evaluation + the decision caches moved to the engine
// (RestrictionEngine.m); the matching moved to Ruleset.m. These public
// methods keep their signatures and behavior.

@interface ShadowBackend () {
    ShadowRulesetStore* store;
    ShadowRestrictionEngine* engine;
}
@end

@implementation ShadowBackend

- (instancetype)init {
    if((self = [super init])) {
        store = [ShadowRulesetStore new];
        engine = [[ShadowRestrictionEngine alloc] initWithStore:store];
    }

    return self;
}

// C0-5: current ruleset generation (incremented on every snapshot swap), read
// atomically; consumers use it to invalidate caches on ruleset reload.
- (NSUInteger)rulesetGeneration {
    return [store generation];
}

- (BOOL)isPathRestricted:(NSString *)path {
    return [engine isPathRestricted:path];
}

// Candidate 5: typed entry point (the dictionary methods translate via Core.m).
- (BOOL)isPathRestrictedQuery:(ShadowRestrictionQuery *)query {
    return [engine isPathRestrictedQuery:query];
}

- (BOOL)isSchemeRestricted:(NSString *)scheme {
    return [engine isSchemeRestricted:scheme];
}

// C0-3: ruleset-driven bundle-ID check (the static well-known list lives in
// -[Shadow isBundleIDRestricted:], which consults this for the user-extensible
// half).
- (BOOL)isBundleIDRestricted:(NSString *)bundleID {
    return [engine isBundleIDRestricted:bundleID];
}
@end