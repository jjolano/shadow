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

// Installed-state bitset, indexed by unit index in the SHDWInstallUnits()
// table. The installer table's row order must match the metadata table's
// order (SHDWHookInstaller carries unitID precisely so the coordinator can
// cross-check and, if they ever disagree, fall back to a per-ID lookup).
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
    SHDWHookInstaller _installers[SHDW_MAX_UNITS];
    NSUInteger _installerCount;
    uint64_t _installedBits;          // bitset: bit i = unit i installed
    BOOL _escalated;
    BOOL _installing;                 // re-entrancy guard (see installEventSync:)
    NSArray<NSString*>* _ctorInventory;
    NSArray<NSString*>* _postLoadInventory;
    NSArray<NSString*>* _postDetectorInventory;
}
@property (nonatomic, readwrite) SHDWBackendSet* backends;
@property (nonatomic, readwrite, copy) NSDictionary<NSString*, id>* prefs;
@property (nonatomic, readwrite) dispatch_queue_t lifecycleQueue;  // serial
+ (NSDictionary<NSString*, id>*)shdw_activationSnapshot;
+ (NSDictionary<NSString*, id>*)shdw_identitySnapshotForBundleID:(NSString*)bundleID scheme:(NSString*)scheme;
+ (NSDictionary<NSString*, id>*)shdw_identityImageForAddress:(NSValue*)address;
- (NSDictionary<NSString*, id>*)shdw_activationSnapshot;
@end

@implementation SHDWBackendSet
@end

@implementation SHDWHookCoordinator

- (instancetype)initWithInstallerTable:(const SHDWHookInstaller*)installers
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
    _lifecycleQueue = dispatch_queue_create("com.shadow.hookcoordinator.lifecycle", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_set_specific(_lifecycleQueue, &kSHDWHookCoordinatorQueueKey, (__bridge void*)self, NULL);

    SHDWBackendSet* set = [SHDWBackendSet new];
    set.hooks = [SHDWHookSession new];
    // HK3 reports each hook request individually. These bits therefore mean
    // "the native request exists", not that a legacy provider was discovered
    // before the request had a chance to route.
    set.capabilities = SHDWCapMessage | SHDWCapFunction |
                       SHDWCapInline | SHDWCapPrivateSym;
    self.backends = set;
    gSHDWActivationCoordinator = self;

    return self;
}

#pragma mark - Unit lookup

- (NSArray<NSString*>*)installedUnitIDs {
    NSUInteger count = 0;
    const SHDWInstallUnit* units = SHDWInstallUnits(&count);
    NSMutableArray<NSString*>* inventory = [NSMutableArray new];

    for(NSUInteger i = 0; i < count && i < SHDW_MAX_UNITS; i++) {
        if((_installedBits >> i) & 1ULL) {
            [inventory addObject:[NSString stringWithUTF8String:units[i].unitID]];
        }
    }

    return [inventory copy];
}

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
    }
}

- (NSDictionary<NSString*, id>*)shdw_activationSnapshot {
    __block NSDictionary<NSString*, id>* snapshot = nil;
    void (^copyState)(void) = ^{
        snapshot = @{
            @"ctor_inventory" : _ctorInventory ?: @[],
            @"post_load_inventory" : _postLoadInventory ?: @[],
            @"post_detector_inventory" : _postDetectorInventory ?: @[],
            @"ctor_observed" : @(_ctorInventory != nil),
            @"post_load_observed" : @(_postLoadInventory != nil),
            @"post_detector_observed" : @(_postDetectorInventory != nil),
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
    return gSHDWActivationCoordinator ? [gSHDWActivationCoordinator shdw_activationSnapshot] : nil;
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
    const SHDWInstallUnit* units = SHDWInstallUnits(&count);

    for(NSUInteger i = 0; i < count; i++) {
        if([[NSString stringWithUTF8String:units[i].unitID] isEqualToString:unitID]) {
            return i;
        }
    }

    return NSNotFound;
}

- (const SHDWHookInstaller*)installerForUnitID:(NSString*)unitID {
    for(NSUInteger i = 0; i < _installerCount; i++) {
        if(strcmp(_installers[i].unitID, unitID.UTF8String) == 0) {
            return &_installers[i];
        }
    }

    return NULL;
}

#pragma mark - Event install

- (NSUInteger)installEvent:(SHDWLifecycleEvent)event {
    // Re-entrancy guard: the installers dlopen dylibs, which fires dyld
    // add-image callbacks that call back into installEvent on this same
    // lifecycle-queue thread. dispatch_sync to the queue we are already
    // executing on would deadlock (observed: "_dispatch_sync_f_slow: called on
    // queue already owned by current thread" — the ShadowHarness crash).
    // _installing is set BEFORE dispatch_sync so the dyld callback's
    // installEvent call is caught by this guard. A nested install is a no-op:
    // _installedBits makes installEventSync idempotent per unit.
    if(_installing) {
        return 0;
    }

    _installing = YES;  // Set BEFORE dispatch_sync to catch dyld callbacks

    __block NSUInteger installed = 0;

    dispatch_sync(self.lifecycleQueue, ^{
        installed = [self installEventSync:event];
    });

    _installing = NO;

    return installed;
}

- (NSUInteger)installEventSync:(SHDWLifecycleEvent)event {
    // Worker function for installEvent / escalateWithReason. Runs on the
    // lifecycle queue, or on main for the ObjC-heavy detector escalation.
    // Does NOT manage _installing — installEvent: owns that flag.
    // Idempotency is handled by _installedBits: a unit already installed by an
    // earlier event is skipped, so a re-entrant call from a detector trip
    // during an install is a no-op for already-installed units.
    NSArray<NSString*>* plan = SHDWHookPlan(self.prefs, self.backends.capabilities, event);

    if(!plan.count) {
        [self recordActivationInventoryForEvent:event];
        return 0;
    }

    NSUInteger localInstalled = 0;

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

        NSUInteger unitCount = 0;
        const SHDWInstallUnit* units = SHDWInstallUnits(&unitCount);
        const SHDWInstallUnit* unit = index < unitCount ? &units[index] : NULL;
        const SHDWHookInstaller* installer = [self installerForUnitID:unitID];

        if(!installer) {
            NSLog(@"[Shadow][coordinator] no installer for unit %@", unitID);
            continue;
        }

        NSLog(@"[Shadow][coordinator] + %s", unit->unitID);

        SHDWHookSession* previous = SHDWHookSessionSetCurrent(self.backends.hooks);
        @try {
            installer->install(self.backends.hooks);
        } @finally {
            SHDWHookSessionSetCurrent(previous);
        }
        _installedBits |= (1ULL << index);
        localInstalled++;
    }

    [self recordActivationInventoryForEvent:event];

    return localInstalled;
}

- (void)escalateWithReason:(NSString*)reason {
    (void) reason;

    if(__atomic_exchange_n(&_escalated, YES, __ATOMIC_ACQ_REL)) {
        return;
    }

    // Tier-2 installs ObjC hooks, so run it on the main queue after the
    // detector's intercepted stack has unwound.
    dispatch_async(dispatch_get_main_queue(), ^{
        [self installEventSync:SHDWEventDetectorEscalation];
    });
}

@end
