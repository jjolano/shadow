#ifndef hook_coordinator_h
#define hook_coordinator_h

#import <Foundation/Foundation.h>
#import <Shadow/HookConfiguration.h>
#import "SHDWHookSession.h"

typedef struct {
    const char* unitID;
    void (*install)(SHDWHookSession* hooks);
    void (*verify)(void);
} SHDWHookInstaller;

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
- (void)escalateWithReason:(NSString*)reason;

@end

#endif
