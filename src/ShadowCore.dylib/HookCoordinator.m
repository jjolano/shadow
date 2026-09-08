#import "HookCoordinator.h"

#import <Shadow/Core.h>

#import <dlfcn.h>
#import <errno.h>
#import <mach-o/dyld.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>

// Installed-state bitset, indexed by plugin index in SHDWPluginRegistry()
// (renamed from SHDWInstallUnits). The installer table's row order should
// match the metadata table's order for the hook plugins (SHDWPluginInstaller
// carries pluginID/unitID precisely so the coordinator can cross-check and,
// if they ever disagree, fall back to a per-ID lookup). Policy plugins have
// no installer (they are evaluated via RestrictionEngine).
#define SHDW_MAX_UNITS 64

static char kSHDWHookCoordinatorQueueKey;
static SHDWHookCoordinator* gSHDWActivationCoordinator = nil;

// Defined by the runtime dyld hook.  Keep the identity probe on the same
// exact-path predicate the hook layer uses; a second local path list would
// make the probe capable of validating a different contract.
extern BOOL shdw_is_shadow_runtime_image(const char* path);

static NSString* shdw_identity_pointer_string(const void* pointer) {
    return [NSString stringWithFormat:@"0x%llx", (unsigned long long)(uintptr_t)pointer];
}

static NSDictionary<NSString*, id>* shdw_identity_image_for_address(const void* address) {
    Dl_info info = {0};
    BOOL resolved = dladdr(address, &info) != 0;
    const char* imagePath = resolved ? info.dli_fname : NULL;
    const struct mach_header* header = resolved ? (const struct mach_header*)info.dli_fbase : NULL;
    uintptr_t base = UINTPTR_MAX, end = 0;

    if(header) {
        uint32_t count = _dyld_image_count();

        for(uint32_t i = 0; i < count; i++) {
            if(_dyld_get_image_header(i) != header) {
                continue;
            }

            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            const struct load_command* command = (const void *)((const struct mach_header_64 *)header + 1);

            for(uint32_t j = 0; j < header->ncmds; j++) {
                if(command->cmdsize < sizeof(*command)) {
                    break;
                }

                if(command->cmd == LC_SEGMENT_64 && command->cmdsize >= sizeof(struct segment_command_64)) {
                    const struct segment_command_64* segment = (const void *)command;
                    uintptr_t segmentBase = (uintptr_t)segment->vmaddr + (uintptr_t)slide;
                    uintptr_t segmentEnd = segmentBase + (uintptr_t)segment->vmsize;

                    if(segmentBase < base) {
                        base = segmentBase;
                    }

                    if(segmentEnd > end) {
                        end = segmentEnd;
                    }
                }

                command = (const struct load_command *)((const char *)command + command->cmdsize);
            }

            break;
        }
    }

    return @{
        @"image_path" : imagePath ? @(imagePath) : [NSNull null],
        @"mapped_range" : end > base ? @{
            @"base" : shdw_identity_pointer_string((const void *)base),
            @"end" : shdw_identity_pointer_string((const void *)end),
        } : [NSNull null],
        @"caller_address" : shdw_identity_pointer_string(address),
        @"canonical_runtime" : @(imagePath && shdw_is_shadow_runtime_image(imagePath)),
    };
}

@interface SHDWBackendSet ()   // readwrite backing for the init-time fill
@property (nonatomic, readwrite) SHDWHookSession* hooks;
@property (nonatomic, readwrite) SHDWCapabilities capabilities;
@end

@interface SHDWHookCoordinator () {
    SHDWPluginInstaller _installers[SHDW_MAX_UNITS];
    NSUInteger _installerCount;
    uint64_t _installedBits;          // bitset: bit i = unit i installed
    BOOL _escalated;
    BOOL _prearmed;
    BOOL _sdkFallbackInstalled;
    BOOL _harnessProfile;
    BOOL _installing;                 // re-entrancy guard (see installEventSync:)
    NSUInteger _pendingEvents;          // bitset over SHDWLifecycleEvent: events
                                        // that arrived while _installing, replayed
                                        // on drain (a dropped UIKit event would
                                        // otherwise lose its hooks forever)
    NSArray<NSString*>* _ctorInventory;
    NSArray<NSString*>* _postLoadInventory;
    NSArray<NSString*>* _postDetectorInventory;
    NSArray<NSString*>* _postSDKFallbackInventory;
}
@property (nonatomic, readwrite) SHDWBackendSet* backends;
@property (nonatomic, readwrite, copy) NSDictionary<NSString*, id>* prefs;
@property (nonatomic, readwrite) dispatch_queue_t lifecycleQueue;  // serial
+ (NSDictionary<NSString*, id>*)shdw_activationSnapshot;
+ (NSDictionary<NSString*, id>*)shdw_identitySnapshotForBundleID:(NSString*)bundleID scheme:(NSString*)scheme;
+ (NSDictionary<NSString*, id>*)shdw_identityImageForAddress:(NSValue*)address;
- (NSDictionary<NSString*, id>*)shdw_activationSnapshot;
+ (SHDWHookCoordinator*)activationCoordinator;
@end

@implementation SHDWBackendSet
@end

@implementation SHDWHookCoordinator

- (instancetype)initWithInstallerTable:(const SHDWPluginInstaller*)installers
                                 count:(NSUInteger)count
                                 prefs:(NSDictionary<NSString*, id>*)prefs {
    self = [super init];

    if(!self) {
        return nil;
    }

    _installerCount = MIN(count, SHDW_MAX_UNITS);

    for(NSUInteger i = 0; i < _installerCount; i++) {
        _installers[i] = installers[i];
    }

    _prefs = [prefs copy];
    _harnessProfile = _prefs[SHDWUniversalHarnessBaselineID] != nil;
    _lifecycleQueue = dispatch_queue_create("com.shadow.hookcoordinator.lifecycle", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_set_specific(_lifecycleQueue, &kSHDWHookCoordinatorQueueKey, (__bridge void*)self, NULL);

    // HK_Library troubleshooting override: first try this process's
    // function/memory hooks on one backend engine. "auto" (the default)
    // leaves routing alone; a clean override refusal retries automatic routing.
    id hookLibrary = _prefs[SHDWHookLibraryID];
    SHDWSetProcessBackendOverride([hookLibrary isKindOfClass:[NSString class]]
        ? [(NSString*)hookLibrary UTF8String] : NULL);

    SHDWBackendSet* set = [SHDWBackendSet new];
    set.hooks = [[SHDWHookSession alloc] initWithLifecycleQueue:_lifecycleQueue];
    // HK3 reports each hook request individually. These bits therefore mean
    // "the native request exists", not that a legacy provider was discovered
    // before the request had a chance to route.
    set.capabilities = SHDWCapMessage | SHDWCapFunction |
                       SHDWCapInline | SHDWCapPrivateSym;
    self.backends = set;
    @synchronized([SHDWHookCoordinator class]) {
        gSHDWActivationCoordinator = self;
    }

    return self;
}

#pragma mark - Unit lookup

- (NSArray<NSString*>*)installedUnitIDs {
    NSUInteger count = 0;
    const SHDWPlugin* plugins = SHDWPluginRegistry(&count);
    NSMutableArray<NSString*>* inventory = [NSMutableArray new];

    for(NSUInteger i = 0; i < count && i < SHDW_MAX_UNITS; i++) {
        if((_installedBits >> i) & 1ULL) {
            [inventory addObject:[NSString stringWithUTF8String:plugins[i].unitID]];
        }
    }

    return [inventory copy];
}
- (NSArray<NSString*>*)installedPluginIDs { return [self installedUnitIDs]; }

- (void)recordActivationInventoryForEvent:(SHDWLifecycleEvent)event {
    NSArray<NSString*>* inventory = [self installedUnitIDs];

    switch(event) {
        case SHDWEventCtor:
            _ctorInventory = inventory;
            break;
        case SHDWEventUIKitLoaded:
            _postLoadInventory = inventory;
            break;
        case SHDWEventDetectorEscalation:
            _postDetectorInventory = inventory;
            break;
        case SHDWEventSDKFallback:
            _postSDKFallbackInventory = inventory;
            break;
    }
}

- (NSDictionary<NSString*, id>*)shdw_activationSnapshot {
    __block NSDictionary<NSString*, id>* snapshot = nil;
    void (^copyState)(void) = ^{
        snapshot = @{
            @"ctor_inventory" : _ctorInventory ?: @[],
            @"post_load_inventory" : _postLoadInventory ?: @[],
            @"post_detector_inventory" : _postDetectorInventory ?: @[],
            @"sdk_fallback_inventory" : _postSDKFallbackInventory ?: @[],
            @"ctor_observed" : @(_ctorInventory != nil),
            @"post_load_observed" : @(_postLoadInventory != nil),
            @"post_detector_observed" : @(_postDetectorInventory != nil),
            @"sdk_fallback_observed" : @(_postSDKFallbackInventory != nil),
            @"escalated" : @(_escalated),
        };
    };

    if(dispatch_get_specific(&kSHDWHookCoordinatorQueueKey) == (__bridge void*)self) {
        copyState();
    } else {
        dispatch_sync(self.lifecycleQueue, copyState);
    }

    return snapshot;
}

+ (NSDictionary<NSString*, id>*)shdw_activationSnapshot {
    return [[self activationCoordinator] shdw_activationSnapshot];
}

+ (SHDWHookCoordinator*)activationCoordinator {
    @synchronized([SHDWHookCoordinator class]) {
        return gSHDWActivationCoordinator;
    }
}

// This is deliberately private runtime instrumentation, like the activation
// snapshot above.  Every observation executes from this canonical Core image;
// the identity battery uses it as the truth control against external fixture
// callers without granting those fixtures an internal-read scope.
+ (NSDictionary<NSString*, id>*)shdw_identitySnapshotForBundleID:(NSString*)bundleID scheme:(NSString*)scheme {
    NSDictionary<NSString*, id>* snapshot = nil;

    SHADOW_INTERNAL_SCOPE {
    struct stat st;
    errno = 0;
    int statResult = stat("/var/jb", &st);
    int statErrno = errno;
    uint32_t imageCount = _dyld_image_count();
    NSUInteger runtimeImages = 0;

    for(uint32_t i = 0; i < imageCount; i++) {
        const char* path = _dyld_get_image_name(i);

        if(path && shdw_is_shadow_runtime_image(path)) {
            runtimeImages += 1;
        }
    }

    (void)dlopen("/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_LAZY | RTLD_LOCAL);

    BOOL proxySupported = NO;
    BOOL proxyPresent = NO;
    BOOL schemeSupported = NO;
    NSInteger schemeCount = NSNotFound;
    Class proxyClass = objc_getClass("LSApplicationProxy");
    SEL proxySelector = sel_registerName("applicationProxyForIdentifier:");

    if(bundleID && proxyClass && class_getClassMethod(proxyClass, proxySelector)) {
        typedef id (*ProxyMessage)(id, SEL, id);
        proxySupported = YES;
        proxyPresent = ((ProxyMessage)objc_msgSend)((id)proxyClass, proxySelector, bundleID) != nil;
    }

    Class workspaceClass = objc_getClass("LSApplicationWorkspace");
    SEL workspaceSelector = sel_registerName("defaultWorkspace");
    SEL schemeSelector = sel_registerName("applicationsAvailableForHandlingURLScheme:");

    if(scheme && workspaceClass && class_getClassMethod(workspaceClass, workspaceSelector)) {
        typedef id (*WorkspaceMessage)(id, SEL);
        id workspace = ((WorkspaceMessage)objc_msgSend)((id)workspaceClass, workspaceSelector);

        if(workspace && [workspace respondsToSelector:schemeSelector]) {
            typedef id (*SchemeMessage)(id, SEL, id);
            id values = ((SchemeMessage)objc_msgSend)(workspace, schemeSelector, scheme);
            schemeSupported = YES;
            schemeCount = values ? [values count] : 0;
        }
    }

    Method method = class_getClassMethod(self, _cmd);
    IMP implementation = method ? method_getImplementation(method) : NULL;
    const char* inserted = getenv("DYLD_INSERT_LIBRARIES");

    snapshot = @{
        @"identity" : shdw_identity_image_for_address((const void *)implementation),
        @"filesystem" : @{ @"result" : @(statResult), @"errno" : @(statErrno) },
        @"dyld" : @{ @"image_count" : @(imageCount), @"runtime_image_count" : @(runtimeImages) },
        @"objc" : @{ @"shadow_present" : @(objc_getClass("Shadow") != Nil) },
        @"process" : @{ @"dyld_insert_present" : @(inserted != NULL) },
        @"app" : @{ @"supported" : @(proxySupported),
                      @"present" : proxySupported ? @(proxyPresent) : [NSNull null] },
        @"url_scheme" : @{ @"supported" : @(schemeSupported),
                             @"result_count" : schemeSupported ? @(schemeCount) : [NSNull null] },
    };
    }

    return snapshot;
}

+ (NSDictionary<NSString*, id>*)shdw_identityImageForAddress:(NSValue*)address {
    NSDictionary<NSString*, id>* image = nil;

    SHADOW_INTERNAL_SCOPE {
        image = shdw_identity_image_for_address(address.pointerValue);
    }

    return image;
}

- (NSUInteger)unitIndexForID:(NSString*)unitID {
    NSUInteger count = 0;
    const SHDWPlugin* plugins = SHDWPluginRegistry(&count);

    for(NSUInteger i = 0; i < count; i++) {
        if([[NSString stringWithUTF8String:plugins[i].unitID] isEqualToString:unitID]) {
            return i;
        }
    }

    return NSNotFound;
}
- (NSUInteger)pluginIndexForID:(NSString*)pluginID { return [self unitIndexForID:pluginID]; }

- (const SHDWPluginInstaller*)installerForUnitID:(NSString*)unitID {
    for(NSUInteger i = 0; i < _installerCount; i++) {
        if(strcmp(_installers[i].unitID, unitID.UTF8String) == 0) {
            return (const SHDWPluginInstaller*)&_installers[i];
        }
    }

    return NULL;
}
- (const SHDWPluginInstaller*)installerForPluginID:(NSString*)pluginID {
    return [self installerForUnitID:pluginID];
}

#pragma mark - Event install

- (NSUInteger)installEvent:(SHDWLifecycleEvent)event {
    if(event < SHDWEventCtor || event > SHDWEventSDKFallback) return 0;
    __block NSUInteger installed = 0;
    __block NSException* failure = nil;
    void (^work)(void) = ^{
        _pendingEvents |= (1UL << (NSUInteger)event);
        if(_installing) return;
        _installing = YES;
        // Coalesce recursive events, including those raised by readiness blocks.
        NSUInteger processed = 0;
        @try {
            while(_pendingEvents & ~processed) {
                NSUInteger pending = _pendingEvents & ~processed;
                _pendingEvents = 0;
                processed |= pending;
                for(NSUInteger e = SHDWEventCtor; e <= SHDWEventSDKFallback; e++) {
                    if((pending >> e) & 1UL) {
                        @try {
                            installed += [self installEventSync:(SHDWLifecycleEvent)e];
                        } @catch(NSException* exception) {
                            if(!failure) failure = exception;
                        }
                        @try {
                            [self.backends.hooks drainPendingTargets];
                        } @catch(NSException* exception) {
                            if(!failure) failure = exception;
                        }
                    }
                }
            }
        } @catch(NSException* exception) {
            if(!failure) failure = exception;
        } @finally {
            _pendingEvents = 0;
            _installing = NO;
        }
    };
    if(dispatch_get_specific(&kSHDWHookCoordinatorQueueKey) == (__bridge void*)self) work();
    else dispatch_sync(self.lifecycleQueue, work);
    if(failure) @throw failure;
    return installed;
}

- (void)enqueueEvent:(SHDWLifecycleEvent)event {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            [self installEvent:event];
        } @catch(NSException* exception) {
            NSLog(@"[Shadow] queued lifecycle event failed: %@", exception);
        }
    });
}

+ (void)shdw_requestPendingTargetDrain {
    static BOOL requested;
    if(__atomic_exchange_n(&requested, YES, __ATOMIC_ACQ_REL)) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        __atomic_store_n(&requested, NO, __ATOMIC_RELEASE);
        SHDWHookCoordinator* coordinator = [self activationCoordinator];
        if(!coordinator) return;
        dispatch_sync(coordinator.lifecycleQueue, ^{
            NSException* failure = nil;
            coordinator->_installing = YES;
            @try {
                [coordinator.backends.hooks drainPendingTargets];
            } @catch(NSException* exception) {
                failure = exception;
            } @finally {
                coordinator->_installing = NO;
            }
            for(NSUInteger e = SHDWEventCtor; e <= SHDWEventSDKFallback; e++) {
                if((coordinator->_pendingEvents >> e) & 1UL) {
                    @try {
                        [coordinator installEvent:(SHDWLifecycleEvent)e];
                    } @catch(NSException* exception) {
                        if(!failure) failure = exception;
                    }
                    break;
                }
            }
            if(failure) NSLog(@"[Shadow] pending target drain failed: %@", failure);
        });
    });
}

- (NSUInteger)installEventSync:(SHDWLifecycleEvent)event {
    // Worker function for installEvent. Always runs on the lifecycle queue
    // (callers block in dispatch_sync, including main-thread escalation);
    // the install itself never runs on main. Does NOT manage _installing or
    // _pendingEvents — installEvent: owns those.
    // Idempotency is handled by _installedBits: a unit already installed by an
    // earlier event is skipped, so a re-entrant call from a detector trip
    // during an install is a no-op for already-installed units.
    if(event == SHDWEventDetectorEscalation) {
        // Anti-fishhook repair before Tier-2 installs: a detector that undid
        // GOT rebinds (direct store, bypassing the vm_protect guard) gets its
        // work reverted first, so the escalation builds on intact hooks.
        // Pure memory compare/store — safe on either queue.
        SHDWRebindRepairSlots();
    }
    NSArray<NSString*>* plan = SHDWPluginPlan(self.prefs, self.backends.capabilities, event);

    if(!plan.count) {
        [self recordActivationInventoryForEvent:event];
        return 0;
    }

    NSUInteger localInstalled = 0;
    NSException* failure = nil;

    for(NSString* unitID in plan) {
        NSUInteger index = [self unitIndexForID:unitID];

        if(index == NSNotFound || index >= SHDW_MAX_UNITS) {
            NSLog(@"[Shadow][coordinator] plan named unknown unit %@", unitID);
            continue;
        }

        // A unit installed by an earlier event is a no-op in later events.
        if((_installedBits >> index) & 1ULL) {
            continue;
        }

        NSUInteger pluginCount = 0;
        const SHDWPlugin* plugins = SHDWPluginRegistry(&pluginCount);
        const SHDWPlugin* plugin = index < pluginCount ? &plugins[index] : NULL;
        const SHDWPluginInstaller* installer = [self installerForUnitID:unitID];

        if(!installer) {
            // Policy plugins have no installer — they are evaluated via RestrictionEngine
            if(plugin && strncmp(plugin->unitID, "Policy_", 7) == 0) {
                _installedBits |= (1ULL << index);
                localInstalled++;
                continue;
            }
            NSLog(@"[Shadow][coordinator] no installer for unit %@", unitID);
            continue;
        }

        NSLog(@"[Shadow][coordinator] + %s", plugin->unitID);

        SHDWHookSession* previous = SHDWHookSessionSetCurrent(self.backends.hooks);
        @try {
            installer->install(self.backends.hooks);
        } @catch(NSException* exception) {
            if(!failure) failure = exception;
        } @finally {
            SHDWHookSessionSetCurrent(previous);
            // An installer may have mutated targets before throwing.
            _installedBits |= (1ULL << index);
        }
        localInstalled++;
    }

    [self recordActivationInventoryForEvent:event];

    if(failure) @throw failure;
    return localInstalled;
}

- (void)escalateWithReason:(NSString*)reason {
    (void) reason;

    if(__atomic_exchange_n(&_escalated, YES, __ATOMIC_ACQ_REL)) {
        return;
    }

    // Tier-2 installs ObjC hooks. Close the verdict race for main-thread
    // probes (canOpenURL / LSWorkspace run on main almost always): install
    // synchronously through the serializing installEvent: so the verdict
    // returns after Tier-2 is present (the install still runs on the
    // lifecycle queue; the caller just blocks for it). Off-main trips keep
    // the async hop so the intercepted stack unwinds first. Both paths own
    // the _installing re-entrancy guard and _installedBits idempotence via
    // installEvent:.
    if([NSThread isMainThread]) {
        [self installEvent:SHDWEventDetectorEscalation];
    } else {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self installEvent:SHDWEventDetectorEscalation];
        });
    }
}

- (void)prearmDetector {
    if(__atomic_exchange_n(&_prearmed, YES, __ATOMIC_ACQ_REL)) {
        return;
    }

    // Explicit detector adapters are known during construction, before any
    // detector code can be on the stack. Install Tier 2 now; the asynchronous
    // path remains for behavioral discoveries made inside intercepted calls.
    // Also install the SDK-fallback event now: the harness's embedded
    // detectors call installHarnessSDKFallback from a worker queue, and the
    // old ordering (prearm consumes the one-shot first) starved it.
    [self installEvent:SHDWEventDetectorEscalation];
    if(_harnessProfile) {
        [self installEvent:SHDWEventSDKFallback];
        __atomic_store_n(&_sdkFallbackInstalled, YES, __ATOMIC_RELEASE);
    }
}

- (BOOL)installHarnessSDKFallback {
    if(!_harnessProfile || __atomic_exchange_n(&_sdkFallbackInstalled, YES, __ATOMIC_ACQ_REL)) {
        return NO;
    }

    [self installEvent:SHDWEventSDKFallback];
    return YES;
}

+ (BOOL)shdw_installHarnessSDKFallback {
    return [[self activationCoordinator] installHarnessSDKFallback];
}

+ (SHDWHookSession*)shdw_sharedHookSession {
    return [self activationCoordinator].backends.hooks;
}

@end
