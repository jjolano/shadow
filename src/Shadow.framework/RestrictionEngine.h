#ifndef shadow_restriction_engine_h
#define shadow_restriction_engine_h

#import "RestrictionQuery.h"
#import <Foundation/Foundation.h>

typedef struct {
  BOOL hasAppSandbox;
  BOOL rootless;
  NSString *bundlePath;
  NSString *homePath;
  NSArray<NSString *> *groupContainerPaths;
} ShadowRestrictionContext;

typedef NS_ENUM(NSInteger, ShadowPseudoSandboxMode) {
  ShadowPseudoSandboxModeOff = 0,
  // Records what Strict would deny and changes no verdict. This is the only
  // mode Settings offers (a switch stores 1).
  ShadowPseudoSandboxModeAudit = 1,
  // Denies the pseudo set on top of the belt. Measured on device (iOS 15.6,
  // rootless): with this armed the harness launches but never produces a
  // report, so an instrumented app cannot complete a run — the pseudo deny set
  // is wider than a real app sandbox's. Deliberately not offered in Settings;
  // arm it from the pref to reproduce or to re-measure before widening the
  // allowlist.
  ShadowPseudoSandboxModeStrict = 2,
};

// Complete restriction engine: resolution, ruleset storage/evaluation and
// generation-aware decision caches behind one internal interface.
__attribute__((visibility("hidden")))
@interface ShadowRestrictionEngine : NSObject

- (instancetype)initWithContext:(ShadowRestrictionContext)context;

- (void)configurePseudoSandboxMode:(NSInteger)mode;

// Audit sink: the paths Strict would have denied, newest first. In-memory and
// bounded; empty unless audit mode is on. Hidden class — not ABI surface.
- (NSArray<NSString *> *)auditWouldDenyPaths;
- (NSUInteger)auditWouldDenyCount;

- (BOOL)isPathRestrictedQuery:(ShadowRestrictionQuery *)query;
- (BOOL)isMountPathRestricted:(NSString *)path;

- (BOOL)isSchemeRestricted:(NSString *)scheme;
- (BOOL)isBundleIDRestricted:(NSString *)bundleID;
@end
#endif
