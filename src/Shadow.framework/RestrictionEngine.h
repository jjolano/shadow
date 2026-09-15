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
  // Denies the pseudo set on top of the belt. The set models a container app
  // sandbox: it spares the app's own container and the stock read-only roots
  // and denies what lies outside them (/var/folders, /tmp, /var/db, the parent
  // of every app container) — iOS gives an app its temp inside its container,
  // so those root denials are the containment boundary, not over-reach.
  // Measured on device (iOS 15.6, rootless): with this armed the harness cannot
  // complete a run. The harness is a container-sandboxed app — its entitlements
  // carry only application-identifier and keychain-access-groups, and it owns a
  // data container — so what lets it reach /var/mobile/Documents outside that
  // container is libSandy's file grant, which this mode does not model. That
  // says nothing about normal apps. The gate before surfacing this in Settings
  // is therefore an accessibility enumeration, not an allowlist edit: the
  // harness restriction tests hold a corpus of paths a stock app may reach and
  // fail if any one of them is denied.
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
