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
  // rootless) against a captured app context: the set covers /var/folders (the
  // system temp root), /tmp, /var/mobile (the parent of every app container)
  // and /var/db — all of which a real app sandbox admits. With this armed an
  // instrumented app launches but never completes a run, so it is deliberately
  // not offered in Settings. Pinned by
  // RestrictionTests/TestPseudoSandboxCapturedAppContext; widen the allowlist
  // in shdwPseudoWouldDeny before ever surfacing it.
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
