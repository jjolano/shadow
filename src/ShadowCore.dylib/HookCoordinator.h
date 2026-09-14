#ifndef hook_coordinator_h
#define hook_coordinator_h

#import "SHDWHookSession.h"
#import <Foundation/Foundation.h>
#import <Shadow/SHDWPlugin.h>

// One plugin's installer entry: canonical unit ID (SHDWPlugin.h aliases
// unitID to pluginID) and the function that installs its hooks.
typedef struct {
  const char *pluginID;
  void (*install)(SHDWHookSession *hooks);
} SHDWPluginInstaller;

@interface SHDWBackendSet : NSObject
@property(nonatomic, readonly) SHDWHookSession *hooks;
@property(nonatomic, readonly) SHDWCapabilities capabilities;
@end

// Owns backend resolution, lifecycle ordering, batching, and idempotence for
// every ShadowCore hook install.
@interface SHDWHookCoordinator : NSObject

- (instancetype)initWithInstallerTable:(const SHDWPluginInstaller *)installers
                                 count:(NSUInteger)count
                                 prefs:(NSDictionary<NSString *, id> *)prefs;

@property(nonatomic, readonly) SHDWBackendSet *backends;
@property(nonatomic, readonly) NSDictionary<NSString *, id> *prefs;
@property(nonatomic, readonly, getter=isEscalated) BOOL escalated;

- (NSUInteger)installEvent:(SHDWLifecycleEvent)event;
- (void)enqueueEvent:(SHDWLifecycleEvent)event;
// Coalesced asynchronous notification; never drains on the notifying stack.
+ (void)shdw_requestPendingTargetDrain;
- (void)prearmDetector;
- (void)escalate;
- (BOOL)installHarnessSDKFallback;
+ (BOOL)shdw_installHarnessSDKFallback;
// Process-global hook session for event-driven repair paths (RebindRepair.x)
// that run outside any installer. Nil until the ctor finishes.
+ (SHDWHookSession *)shdw_sharedHookSession;

@end

#endif
