#ifndef shadow_restriction_engine_h
#define shadow_restriction_engine_h

#import <Foundation/Foundation.h>
#import "RestrictionQuery.h"

typedef struct {
    BOOL hasAppSandbox;
    BOOL rootless;
    NSString* bundlePath;
    NSString* homePath;
    NSArray<NSString *> *groupContainerPaths;
} ShadowRestrictionContext;

typedef NS_ENUM(NSInteger, ShadowPseudoSandboxMode) {
    ShadowPseudoSandboxModeOff = 0,
    ShadowPseudoSandboxModeAudit = 1,
    ShadowPseudoSandboxModeStrict = 2,
};

// Complete restriction engine: resolution, ruleset storage/evaluation and
// generation-aware decision caches behind one internal interface.
__attribute__((visibility("hidden")))
@interface ShadowRestrictionEngine : NSObject

- (instancetype)initWithContext:(ShadowRestrictionContext)context;

- (void)configurePseudoSandboxMode:(NSInteger)mode;

- (BOOL)isPathRestrictedQuery:(ShadowRestrictionQuery *)query;

- (BOOL)isSchemeRestricted:(NSString *)scheme;
- (BOOL)isBundleIDRestricted:(NSString *)bundleID;
@end
#endif
