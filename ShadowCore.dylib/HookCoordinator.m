// SHDWHookCoordinator — see HookCoordinator.h. Additive machinery; dylib.x
// does not route through it yet (step B2 wires the handoff).

#import "HookCoordinator.h"

// Installed-state bitset, indexed by unit index in the SHDWInstallUnits()
// table. The installer table's row order must match the metadata table's
// order (SHDWHookInstaller carries unitID precisely so the coordinator can
// cross-check and, if they ever disagree, fall back to a per-ID lookup).
#define SHDW_MAX_UNITS 64

@interface SHDWBackendSet ()   // readwrite backing for the init-time fill
@property (nonatomic, readwrite) HKSubstitutor* message;
@property (nonatomic, readwrite) HKSubstitutor* rebind;
@property (nonatomic, readwrite) HKSubstitutor* inlineCover;
@property (nonatomic, readwrite) HKSubstitutor* symlookup;
@property (nonatomic, readwrite) HKSubstitutor* privateSym;
@property (nonatomic, readwrite) SHDWCapabilities capabilities;
@end

@interface SHDWHookCoordinator () {
    SHDWHookInstaller _installers[SHDW_MAX_UNITS];
    NSUInteger _installerCount;
    uint64_t _installedBits;          // bitset: bit i = unit i installed
    uint64_t _skippedMessageBits;     // bitset: unit i fail-soft skipped (no message backend)
    BOOL _uikitSeen;                  // recordUIKitImageLoad fired
    BOOL _escalated;
}
@property (nonatomic, readwrite) SHDWBackendSet* backends;
@property (nonatomic, readwrite, copy) NSDictionary<NSString*, id>* prefs;
@property (nonatomic, readwrite) NSUInteger unitCount;
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

    NSUInteger unitMetaCount = 0;
    SHDWInstallUnits(&unitMetaCount);
    _unitCount = unitMetaCount;

    // One-shot v2 backend resolution. Auto-cover routes each function target
    // and HookKit groups batched operations by the backend that won.
    HKSubstitutor* message   = [HKSubstitutor substitutorWithCategory:HK_CAT_MESSAGE];
    HKSubstitutor* rebind    = [HKSubstitutor substitutorWithAutoCoverCategories:@[@(HK_CAT_FUNCTION_REBIND)]];
    HKSubstitutor* inlineCov = [HKSubstitutor substitutorWithAutoCoverCategories:@[@(HK_CAT_FUNCTION_INLINE), @(HK_CAT_FUNCTION_REBIND)]];
    HKSubstitutor* symlookup = inlineCov;
    HKSubstitutor* privSym   = [HKSubstitutor substitutorWithTypes:HK_LIB_NATIVE];
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

    // Mirrors the legacy subInline nil-ness (fishhook-only devices had no
    // inline backend and the escalation skip logged it).
    if(inlineCov.activeType != HK_LIB_NONE) {
        caps |= SHDWCapInline;
    }

    if(privSym.activeType != HK_LIB_NONE) {
        caps |= SHDWCapPrivateSym;
    }

    SHDWBackendSet* set = [SHDWBackendSet new];
    set.message = message;
    set.rebind = rebind;
    set.inlineCover = inlineCov;
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

// Maps a unit's capability kind to the backend the legacy ctor would have
// passed. Mirrors dylib.x exactly: function groups ride the rebind backend
// (subCFunc = subFish, never subMain unless no rebind backend resolved),
// message groups ride the message backend, symlookup rides the auto-cover
// inline-first instance, private-symbol groups ride the
// private-symbol instance.
- (HKSubstitutor*)backendForUnit:(const SHDWInstallUnit*)unit {
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

// Capability gating (mirror legacy):
//   - message groups fail-soft without a message-capable backend (planner
//     already dropped them, but re-check defensively);
//   - private-symbol groups gate on the backend, like legacy
//     subDyldExtra==subMain skip (dlopen_internal needs a
//     private-symbol-capable backend; the log mirrors the legacy message);
//   - everything else installs unconditionally on its pref (legacy: subCFunc
//     always resolves to something).
- (BOOL)unitCapable:(const SHDWInstallUnit*)unit
             index:(NSUInteger)index
              plan:(NSArray<NSString*>*)plan {
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
            // Legacy message, preserved verbatim (dylib.x:628-629 / the
            // escalation skip in shdw_detector_detected).
            NSLog(@"[Shadow][coordinator] dylibex skipped: no private-symbol-capable backend (dlopen_internal needs one)");
            return NO;
        }

        return YES;
    }

    if(unit->capability == SHDWCapabilitySymlookup && !(caps & (SHDWCapInline | SHDWCapFunction))) {
        // Cannot happen in practice (rebind is always resolvable), but keep
        // the fail-soft mirror honest: legacy subSymLookup fell back to
        // subCFunc, which always resolved.
        NSLog(@"[Shadow][coordinator] %s skipped: no rebind/inline backend", unit->unitID);
        return NO;
    }

    (void) index;
    (void) plan;
    return YES;
}

#pragma mark - Batch commit

// Drains the same substitutor instances handed to installers, then runs the
// legacy per-unit verification if any lane reports a failure.
//
// B2a parity: %hook groups expand to HKHookMessage/HKHookFunction, which
// route to [HKSubstitutor defaultSubstitutor] — NOT the instance the
// installer passed. The legacy ctor drained that same default instance via
// the global HKExecuteBatch()/HKDisableBatching() (dylib.x:664-665), so the
// coordinator drains the default substitutor's queue here too, exactly once
// per event, before the per-instance drain. Both drains are unconditional
// (executeHooks on an empty queue is a no-op; setBatching: is idempotent).
- (void)commitBatch:(NSArray<NSString*>*)unitIDs {
    // Legacy global batch drain (HKExecuteBatch/HKDisableBatching): covers
    // every %hook/%function Logos group, which queue on the default
    // substitutor regardless of the instance passed to the installer.
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

        // Idempotence per event: legacy _shdw_*_installed guards. The bitset
        // makes a unit installed by an earlier event a no-op in a later one
        // (e.g. a ctor-installed group re-named by the escalation plan).
        if((_installedBits >> index) & 1ULL) {
            continue;
        }

        const SHDWInstallUnit* unit = SHDWUnitAt(index);
        const SHDWHookInstaller* installer = [self installerForUnitID:unitID];

        if(!installer) {
            NSLog(@"[Shadow][coordinator] no installer for unit %@", unitID);
            continue;
        }

        if(![self unitCapable:unit index:index plan:plan]) {
            if(unit->capability == SHDWCapabilityMessage) {
                _skippedMessageBits |= (1ULL << index);
            }

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

- (void)recordUIKitImageLoad {
    // The image watcher itself arrives in a later step; dylib.x still owns
    // _dyld_register_func_for_add_image. Recording here keeps the
    // coordinator's event model complete so the B2 cutover only moves the
    // registration, not the logic.
    dispatch_sync(self.lifecycleQueue, ^{
        _uikitSeen = YES;
    });
}

- (BOOL)isUnitInstalledAtIndex:(NSUInteger)index {
    __block BOOL installed = NO;

    dispatch_sync(self.lifecycleQueue, ^{
        installed = index < SHDW_MAX_UNITS && ((_installedBits >> index) & 1ULL);
    });

    return installed;
}

- (BOOL)isUnitInstalledWithID:(NSString*)unitID {
    NSUInteger index = [self unitIndexForID:unitID];
    return index == NSNotFound ? NO : [self isUnitInstalledAtIndex:index];
}

@end
