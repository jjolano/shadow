#ifndef hook_coordinator_h
#define hook_coordinator_h

#import <Foundation/Foundation.h>
#import <Shadow/SHDWPlugin.h>
#import "SHDWHookSession.h"

// Plugin installer — renamed from SHDWHookInstaller (alias kept)
typedef struct {
    const char* pluginID;
    void (*install)(SHDWHookSession* hooks);
    void (*verify)(void);
} SHDWPluginInstaller;
typedef SHDWPluginInstaller SHDWHookInstaller;
#ifndef pluginID
// unitID alias handled in SHDWPlugin.h; keep installer field consistent
#endif

@interface SHDWBackendSet : NSObject
@property (nonatomic, readonly) SHDWHookSession* hooks;
@property (nonatomic, readonly) SHDWCapabilities capabilities;
@end

// Owns backend resolution, lifecycle ordering, batching, and idempotence for
// every ShadowCore hook install.
@interface SHDWHookCoordinator : NSObject

- (instancetype)initWithInstallerTable:(const SHDWHookInstaller*)installers
                                 count:(NSUInteger)count
                                 prefs:(NSDictionary<NSString*, id>*)prefs;

@property (nonatomic, readonly) SHDWBackendSet* backends;
@property (nonatomic, readonly) NSDictionary<NSString*, id>* prefs;
@property (nonatomic, readonly, getter=isEscalated) BOOL escalated;

- (NSUInteger)installEvent:(SHDWLifecycleEvent)event;
- (void)prearmDetector;
- (void)escalateWithReason:(NSString*)reason;

@end

#endif
