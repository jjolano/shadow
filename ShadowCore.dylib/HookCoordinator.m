#import "HookCoordinator.h"

// Installed-state bitset, indexed by unit index in the SHDWInstallUnits()
// table. The installer table's row order must match the metadata table's
// order (SHDWHookInstaller carries unitID precisely so the coordinator can
// cross-check and, if they ever disagree, fall back to a per-ID lookup).
#define SHDW_MAX_UNITS 64

@interface SHDWBackendSet ()   // readwrite backing for the init-time fill
@property (nonatomic, readwrite) HKSubstitutor* message;
@property (nonatomic, readwrite) HKSubstitutor* rebind;
@property (nonatomic, readwrite) HKSubstitutor* symlookup;
@property (nonatomic, readwrite) HKSubstitutor* privateSym;
@property (nonatomic, readwrite) SHDWCapabilities capabilities;
@end

@interface SHDWHookCoordinator () {
    SHDWHookInstaller _installers[SHDW_MAX_UNITS];
    NSUInteger _installerCount;
    uint64_t _installedBits;          // bitset: bit i = unit i installed
    BOOL _escalated;
}
@property (nonatomic, readwrite) SHDWBackendSet* backends;
@property (nonatomic, readwrite, copy) NSDictionary<NSString*, id>* prefs;
@property (nonatomic, readwrite) dispatch_queue_t lifecycleQueue;  // serial
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

    // Resolve each lane once. Auto-cover routes each function target and
    // HookKit groups batched operations by the backend that won.
    HKSubstitutor* message   = [HKSubstitutor substitutorWithCategory:HK_CAT_MESSAGE];
    HKSubstitutor* rebind    = [HKSubstitutor substitutorWithAutoCoverCategories:@[@(HK_CAT_FUNCTION_REBIND)]];
    HKSubstitutor* inlineCov = [HKSubstitutor substitutorWithAutoCoverCategories:@[@(HK_CAT_FUNCTION_INLINE), @(HK_CAT_FUNCTION_REBIND)]];
    HKSubstitutor* symlookup = inlineCov;
    HKSubstitutor* privSym   = [HKSubstitutor substitutorWithTypes:HK_LIB_NATIVE];

    NSString* preferredID = prefs[SHDWHookLibraryID];
    if(preferredID && ![preferredID isEqualToString:@"auto"]) {
        hookkit_lib_t available = [HKSubstitutor getAvailableSubstitutorTypes];

        for(NSDictionary* info in [HKSubstitutor getSubstitutorTypeInfo:available]) {
            hookkit_lib_t type = (hookkit_lib_t)[info[@"type"] unsignedIntValue];

            if([preferredID isEqualToString:info[@"id"]] && (available & type) && !(type & HK_LIB_SWIFT)) {
                rebind = [HKSubstitutor substitutorWithTypes:type];
                break;
            }
        }
    }

    if(privSym.activeType == HK_LIB_NONE) {
        privSym = [HKSubstitutor substitutorWithOrderedCategories:@[@(HK_CAT_PRIVATE_SYMBOL), @(HK_CAT_MESSAGE)]];
    }
    // activeType == HK_LIB_NONE means the category resolved no backend.
    SHDWCapabilities caps = 0;

    if(message.activeType != HK_LIB_NONE) {
        caps |= SHDWCapMessage;
    }

    if(rebind.activeType != HK_LIB_NONE) {
        caps |= SHDWCapFunction;
    }

    if([HKSubstitutor getAvailableCategories] & HK_CAT_FUNCTION_INLINE) {
        caps |= SHDWCapInline;
    }

    if(privSym.activeType != HK_LIB_NONE) {
        caps |= SHDWCapPrivateSym;
    }

    SHDWBackendSet* set = [SHDWBackendSet new];
    set.message = message;
    set.rebind = rebind;
    set.symlookup = symlookup;
    set.privateSym = privSym;
    set.capabilities = caps;
    self.backends = set;

    if(!(caps & SHDWCapMessage)) {
        NSLog(@"[Shadow][coordinator] no ObjC-capable hooking library available (only fishhook); skipping ObjC-method hook groups");
    }

    if(!(caps & SHDWCapPrivateSym)) {
        NSLog(@"[Shadow][coordinator] no private-symbol-capable backend (dlopen_internal needs one)");
    }

    return self;
}

#pragma mark - Unit lookup

static const SHDWInstallUnit* SHDWUnitAt(NSUInteger index) {
    NSUInteger count = 0;
    const SHDWInstallUnit* units = SHDWInstallUnits(&count);
    return index < count ? &units[index] : NULL;
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

#pragma mark - Backend selection per capability kind

// Map each install-unit capability to its dedicated backend lane.
- (HKSubstitutor*)backendForUnit:(const SHDWInstallUnit*)unit {
    // These C-runtime identity groups require a message-capable provider to
    // be present, but their individual targets use inline-first auto-cover.
    if(strcmp(unit->unitID, "objc") == 0 || strcmp(unit->unitID, "classes") == 0) {
        return self.backends.symlookup;
    }

    switch(unit->capability) {
        case SHDWCapabilityMessage:
            return self.backends.message;
        case SHDWCapabilitySymlookup:
            return self.backends.symlookup;
        case SHDWCapabilityPrivateSym:
            return self.backends.privateSym;
        case SHDWCapabilityFunction:
        case SHDWCapabilityNone:
        default:
            return self.backends.rebind ?: self.backends.message;
    }
}

- (BOOL)unitCapable:(const SHDWInstallUnit*)unit {
    SHDWCapabilities caps = self.backends.capabilities;

    if(unit->capability == SHDWCapabilityMessage) {
        if(!(caps & SHDWCapMessage)) {
            NSLog(@"[Shadow][coordinator] %s skipped: no ObjC-capable backend", unit->unitID);
            return NO;
        }

        return YES;
    }

    if(unit->capability == SHDWCapabilityPrivateSym) {
        if(!(caps & SHDWCapPrivateSym)) {
            NSLog(@"[Shadow][coordinator] dylibex skipped: no private-symbol-capable backend (dlopen_internal needs one)");
            return NO;
        }

        return YES;
    }

    if(unit->capability == SHDWCapabilitySymlookup && !(caps & (SHDWCapInline | SHDWCapFunction))) {
        NSLog(@"[Shadow][coordinator] %s skipped: no rebind/inline backend", unit->unitID);
        return NO;
    }

    return YES;
}

#pragma mark - Batch commit

// %hook/%function groups use HookKit's default substitutor; explicit hook
// functions use the lane passed by the installer. Drain both sets.
- (void)commitBatch:(NSArray<NSString*>*)unitIDs {
    BOOL failed = HKExecuteBatch() != HK_OK;
    HKDisableBatching();

    for(HKSubstitutor* lane in @[self.backends.message, self.backends.rebind,
                                 self.backends.symlookup, self.backends.privateSym]) {
        failed |= [lane executeHooks] != HK_OK;
        [lane setBatching:NO];
    }

    if(!failed || !unitIDs.count) {
        return;
    }

    NSLog(@"[Shadow][coordinator] batch install failed — running per-unit verify");

    for(NSString* unitID in unitIDs) {
        const SHDWHookInstaller* installer = [self installerForUnitID:unitID];

        if(installer && installer->verify) {
            installer->verify();
        }
    }
}

#pragma mark - Event install

- (NSUInteger)installEvent:(SHDWLifecycleEvent)event {
    __block NSUInteger installed = 0;

    dispatch_sync(self.lifecycleQueue, ^{
        installed = [self installEventSync:event];
    });

    return installed;
}

- (NSUInteger)installEventSync:(SHDWLifecycleEvent)event {
    NSArray<NSString*>* plan = SHDWHookPlan(self.prefs, self.backends.capabilities, event);

    if(!plan.count) {
        return 0;
    }

    NSMutableArray<NSString*>* attempted = [NSMutableArray new];
    NSUInteger localInstalled = 0;

    HKEnableBatching();
    for(HKSubstitutor* lane in @[self.backends.message, self.backends.rebind,
                                 self.backends.symlookup, self.backends.privateSym]) {
        [lane setBatching:YES];
    }

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

        const SHDWInstallUnit* unit = SHDWUnitAt(index);
        const SHDWHookInstaller* installer = [self installerForUnitID:unitID];

        if(!installer) {
            NSLog(@"[Shadow][coordinator] no installer for unit %@", unitID);
            continue;
        }

        if(![self unitCapable:unit]) {
            continue;
        }

        NSLog(@"[Shadow][coordinator] + %s", unit->unitID);

        installer->install([self backendForUnit:unit]);
        _installedBits |= (1ULL << index);
        localInstalled++;
        [attempted addObject:unitID];
    }

    [self commitBatch:attempted];

    return localInstalled;
}

- (void)escalateWithReason:(NSString*)reason {
    (void) reason;

    dispatch_sync(self.lifecycleQueue, ^{
        if(_escalated) {
            return;
        }

        _escalated = YES;
        [self installEventSync:SHDWEventDetectorEscalation];
    });
}

@end
