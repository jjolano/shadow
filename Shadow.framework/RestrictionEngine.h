#ifndef shadow_restriction_engine_h
#define shadow_restriction_engine_h

#import <Foundation/Foundation.h>
#import "RestrictionQuery.h"

typedef struct {
    BOOL hasAppSandbox;
    BOOL rootless;
    NSString* bundlePath;
    NSString* homePath;
} ShadowRestrictionContext;

// Complete restriction engine: resolution, ruleset storage/evaluation and
// generation-aware decision caches behind one internal interface.
__attribute__((visibility("hidden")))
@interface ShadowRestrictionEngine : NSObject

- (instancetype)initWithContext:(ShadowRestrictionContext)context;

- (BOOL)isPathRestrictedQuery:(ShadowRestrictionQuery *)query;

- (BOOL)isSchemeRestricted:(NSString *)scheme;
- (BOOL)isBundleIDRestricted:(NSString *)bundleID;
@end
#endif
