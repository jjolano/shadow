// CoordinatorTests — host-runnable, self-contained checks for the B1
// HookCoordinator machinery (ShadowCore.dylib/HookCoordinator.{h,m}) and its
// frozen metadata dependency (Shadow.framework/HookConfiguration.h).
//
// The coordinator's device-facing surface (HookKit substitutor resolution,
// batch commit, event install) can only run on a hooked device; the host
// harness cannot link HookKit. What CAN be validated here — and what step B2
// depends on not drifting — is the pure planner contract the coordinator
// drives:
//   - prefs + capabilities + event → ordered unit IDs (planner),
//   - idempotence + escalation ordering,
//   - install-unit ID ↔ plist pref-key consistency,
//   - group ↔ capability coverage,
//   - standard preset == shipped defaults,
//   - no dead groups.
//
// RunCoordinatorTests() returns the failure count (0 = clean); the harness
// (tests/main.m) calls it. Self-contained: does not link the dylib or
// HookKit, only the framework sources the harness already builds
// (HookConfiguration.m is in the harness SRCS).
//
// The assertions below are the exact contract the coordinator's
// installEvent: consumes. If a metadata change breaks them, the coordinator
// silently skips or mis-routes a unit at install time — that is precisely
// the drift this file exists to catch.

#import <Foundation/Foundation.h>
#import <Shadow/HookConfiguration.h>
#import "../Shadow.framework/SettingsMigration.h"
#import "../ShadowCore.dylib/HookAdapterBridge.h"

#import <string.h>
#import <stdio.h>

static int cg = 0;   // passed
static int cf = 0;   // failed

#define CHECK(_cond, _name) do { \
    if(_cond) { cg++; } else { cf++; printf("FAIL: %s\n", _name); } \
} while(0)

static BOOL IDInPlan(NSArray<NSString*>* plan, const char* unitID) {
    NSString* needle = [NSString stringWithUTF8String:unitID];
    return [plan containsObject:needle];
}

static NSDictionary* DefaultsFor(NSString* key, BOOL value) {
    NSMutableDictionary* prefs = [SHDWDefaultHookSettings() mutableCopy];
    prefs[key] = @(value);
    return prefs;
}

// Full prefs (every hook key on). The planner gates on prefKey only, so a
// full-on dictionary exercises every unit the event can name.
static NSDictionary* AllOnPrefs(void) {
    NSMutableDictionary* prefs = [SHDWDefaultHookSettings() mutableCopy];
    prefs[SHDWUniversalFilesystemID] = @(YES);
    prefs[SHDWUniversalURLSchemeID] = @(YES);
    prefs[SHDWUniversalEnvVarsID] = @(YES);
    prefs[SHDWUniversalFoundationID] = @(YES);
    prefs[SHDWUniversalMachBootstrapID] = @(YES);
    prefs[SHDWUniversalIOKitID] = @(YES);
    prefs[SHDWUniversalLowLevelCID] = @(YES);
    prefs[SHDWUniversalAntiDebuggingID] = @(YES);
    prefs[SHDWUniversalCodeSigningID] = @(YES);
    prefs[SHDWUniversalDynamicLibrariesExtraID] = @(YES);
    prefs[SHDWUniversalSyscallID] = @(YES);
    prefs[SHDWUniversalSandboxID] = @(YES);
    prefs[SHDWUniversalMemoryID] = @(YES);
    prefs[SHDWUniversalHideAppsID] = @(YES);
    prefs[SHDWAdapterDeviceCheckID] = @(YES);
    prefs[SHDWAdapterFreeRASPID] = @(YES);
    prefs[SHDWAdapterDeviceSecurityKitID] = @(YES);
    prefs[SHDWAdapterIOSSecuritySuiteID] = @(YES);
    return prefs;
}

// The exact expected ctor order: canonical table order, restricted to
// ctorInstall units.
static NSArray* ExpectedCtorOrder(void) {
    return @[
        @"Universal_Dyld",
        @"Universal_Filesystem_C",
        @"Universal_EnvVars_C",
        @"Universal_EnvVars_ObjC",
        @"Adapter_DeviceCheck",
        @"Adapter_FreeRASP",
        @"Universal_MachBootstrap",
        @"Universal_IOKit",
        @"Universal_LowLevelC",
        @"Universal_AntiDebugging",
        @"Universal_CodeSigning",
        @"Universal_ObjC",
        @"Universal_ObjC_MethodImplementation",
        @"Universal_Syscall",
        @"Universal_Memory",
        @"Universal_Sandbox",
        @"Universal_HideClasses",
        @"Universal_SymbolLookup",
        @"Universal_DynamicLibrariesExtra",
        @"Adapter_DeviceSecurityKit",
        @"Adapter_IOSSecuritySuite",
    ];
}

static void TestPlannerCtorOrder(void) {
    // Full message+function+inline+private-sym caps: every ctor unit that
    // can install must be named, in canonical order.
    SHDWCapabilities caps = SHDWCapMessage | SHDWCapFunction | SHDWCapInline | SHDWCapPrivateSym;
    NSArray* plan = SHDWHookPlan(AllOnPrefs(), caps, SHDWEventCtor);
    NSArray* expected = ExpectedCtorOrder();

    CHECK([plan isEqualToArray:expected], "ctor plan == canonical install order (all prefs, full caps)");
}

static void TestPlannerGating(void) {
    SHDWCapabilities full = SHDWCapMessage | SHDWCapFunction | SHDWCapInline | SHDWCapPrivateSym;
    SHDWCapabilities fishhookOnly = SHDWCapFunction;   // no message backend

    // Fishhook-only: message units fail-soft out of the ctor plan.
    NSArray* plan = SHDWHookPlan(AllOnPrefs(), fishhookOnly, SHDWEventCtor);
    CHECK(!IDInPlan(plan, "Universal_ObjC"), "no message backend: ObjC fail-soft dropped");
    CHECK(!IDInPlan(plan, "Universal_HideClasses"), "no message backend: class hiding fail-soft dropped");
    CHECK(!IDInPlan(plan, "Universal_EnvVars_ObjC"), "no message backend: EnvVars ObjC fail-soft dropped");
    CHECK(IDInPlan(plan, "Universal_EnvVars_C"), "no message backend: EnvVars C still installs");
    CHECK(IDInPlan(plan, "Universal_Dyld"), "no message backend: dyld still installs");
    CHECK(IDInPlan(plan, "Universal_SymbolLookup"), "no message backend: symbol lookup still installs");

    // Full caps: the same units are present again.
    NSArray* planFull = SHDWHookPlan(AllOnPrefs(), full, SHDWEventCtor);
    CHECK(IDInPlan(planFull, "Universal_ObjC"), "message backend present: ObjC installs");
    CHECK(IDInPlan(planFull, "Universal_HideClasses"), "message backend present: class hiding installs");

    // Pref-off: gated units leave the plan; identity units stay.
    NSDictionary* prefs = DefaultsFor(SHDWUniversalFilesystemID, NO);
    NSArray* planOff = SHDWHookPlan(prefs, full, SHDWEventCtor);
    CHECK(!IDInPlan(planOff, "Universal_Filesystem_C"), "pref off: filesystem C dropped");
    CHECK(IDInPlan(planOff, "Universal_Dyld"), "pref off: dyld still installs");
}

static void TestPlannerUIKit(void) {
    SHDWCapabilities full = SHDWCapMessage | SHDWCapFunction | SHDWCapInline | SHDWCapPrivateSym;

    NSArray* plan = SHDWHookPlan(AllOnPrefs(), full, SHDWEventUIKitLoaded);
    CHECK(([plan isEqualToArray:@[ @"Universal_URLScheme", @"Universal_Foundation_UIKit" ]]), "uikit plan == the two UIKit-class units, in order");

    // Message backend required by the UIKit groups.
    NSArray* planFish = SHDWHookPlan(AllOnPrefs(), SHDWCapFunction, SHDWEventUIKitLoaded);
    CHECK(planFish.count == 0, "no message backend: uikit plan empty");

    // Pref-gated.
    NSDictionary* prefs = DefaultsFor(SHDWUniversalURLSchemeID, NO);
    NSArray* planPref = SHDWHookPlan(prefs, full, SHDWEventUIKitLoaded);
    CHECK(!IDInPlan(planPref, "Universal_URLScheme"), "uikit: URLScheme pref off → dropped");
    CHECK(!IDInPlan(planPref, "Universal_Foundation_UIKit"), "uikit: Foundation default off → dropped");

    NSDictionary* prefsFnd = DefaultsFor(SHDWUniversalFoundationID, YES);
    NSArray* planFnd = SHDWHookPlan(prefsFnd, full, SHDWEventUIKitLoaded);
    CHECK(IDInPlan(planFnd, "Universal_Foundation_UIKit"), "uikit: Foundation pref on → present");
}

static void TestPlannerEscalation(void) {
    SHDWCapabilities full = SHDWCapMessage | SHDWCapFunction | SHDWCapInline | SHDWCapPrivateSym;

    // Canonical escalation order: dylibex first, then tier-2 units in
    // table order (mirrors shdw_detector_detected: dyldextra then tier-2).
    NSArray* plan = SHDWHookPlan(AllOnPrefs(), full, SHDWEventDetectorEscalation);
    NSArray* expected = @[
        @"Universal_DynamicLibrariesExtra",
        @"Universal_DetectorIntegrity",
        @"Universal_Filesystem_ObjC",
        @"Universal_Foundation_ObjC",
        @"Universal_HideApps",
    ];

    CHECK([plan isEqualToArray:expected], "escalation plan == dylibex first, tier-2 in canonical order");

    // dylibex installs even with the pref off (coordinator gates on backend).
    NSDictionary* prefs = DefaultsFor(SHDWUniversalDynamicLibrariesExtraID, NO);
    NSArray* planPref = SHDWHookPlan(prefs, full, SHDWEventDetectorEscalation);
    CHECK(IDInPlan(planPref, "Universal_DynamicLibrariesExtra"), "escalation: dylibex unconditional (backend-gated, not pref-gated)");

    // Idempotence: repeated calls return equal plans (no state).
    CHECK([plan isEqualToArray:SHDWHookPlan(AllOnPrefs(), full, SHDWEventDetectorEscalation)], "escalation plan idempotent");

    // No message backend: tier-2 ObjC units drop, dylibex stays (its
    // capability gate lives in the coordinator).
    NSArray* planFish = SHDWHookPlan(AllOnPrefs(), SHDWCapFunction, SHDWEventDetectorEscalation);
    CHECK(IDInPlan(planFish, "Universal_DynamicLibrariesExtra"), "fishhook-only: dylibex still named (coordinator gates it)");
    CHECK(IDInPlan(planFish, "Universal_DetectorIntegrity"), "fishhook-only: detector integrity still installs");
    CHECK(!IDInPlan(planFish, "Universal_Filesystem_ObjC"), "fishhook-only: tier-2 ObjC dropped");
}

static void TestPlannerSDKFallback(void) {
    SHDWCapabilities full = SHDWCapMessage | SHDWCapFunction | SHDWCapInline | SHDWCapPrivateSym;
    NSArray* productionCtor = SHDWHookPlan(AllOnPrefs(), full, SHDWEventCtor);
    CHECK(IDInPlan(productionCtor, "Adapter_DeviceCheck") &&
          IDInPlan(productionCtor, "Adapter_FreeRASP") &&
          IDInPlan(productionCtor, "Adapter_DeviceSecurityKit") &&
          IDInPlan(productionCtor, "Adapter_IOSSecuritySuite"),
          "production ctor keeps SDK adapters early");

    NSMutableDictionary* harnessPrefs = [AllOnPrefs() mutableCopy];
    harnessPrefs[SHDWUniversalHarnessBaselineID] = @YES;
    NSArray* harnessCtor = SHDWHookPlan(harnessPrefs, full, SHDWEventCtor);
    CHECK(!IDInPlan(harnessCtor, "Adapter_DeviceCheck") &&
          !IDInPlan(harnessCtor, "Adapter_DeviceSecurityKit") &&
          !IDInPlan(harnessCtor, "Adapter_IOSSecuritySuite"),
          "Harness baseline defers SDK adapters");
    CHECK(IDInPlan(harnessCtor, "Adapter_FreeRASP"),
          "Harness baseline keeps one-shot FreeRASP coverage");

    NSMutableDictionary* maximumHarnessPrefs = [AllOnPrefs() mutableCopy];
    maximumHarnessPrefs[SHDWUniversalHarnessBaselineID] = @NO;
    NSArray* maximumHarnessCtor = SHDWHookPlan(maximumHarnessPrefs, full, SHDWEventCtor);
    CHECK(!IDInPlan(maximumHarnessCtor, "Adapter_DeviceCheck") &&
          !IDInPlan(maximumHarnessCtor, "Adapter_DeviceSecurityKit") &&
          !IDInPlan(maximumHarnessCtor, "Adapter_IOSSecuritySuite"),
          "Harness maximum profile defers target-dependent SDK adapters");

    NSArray* fallback = SHDWHookPlan(harnessPrefs, full, SHDWEventSDKFallback);
    NSArray* expectedFallback = @[
        @"Adapter_DeviceCheck", @"Adapter_DeviceSecurityKit", @"Adapter_IOSSecuritySuite",
    ];
    CHECK([fallback isEqualToArray:expectedFallback], "SDK fallback restores deferred adapters in registry order");
    CHECK([SHDWHookPlan(maximumHarnessPrefs, full, SHDWEventSDKFallback) isEqualToArray:expectedFallback],
          "Harness maximum profile installs SDK adapters after detector frameworks load");
}

static void TestInstallUnitConsistency(void) {
    NSUInteger count = 0;
    const SHDWInstallUnit* units = SHDWInstallUnits(&count);

    CHECK(count > 0, "install-unit table non-empty");
    CHECK(count < 64, "install-unit table fits the coordinator bitset");

    NSMutableArray* ids = [NSMutableArray new];
    BOOL allUnique = YES;

    for(NSUInteger i = 0; i < count; i++) {
        NSString* unitID = [NSString stringWithUTF8String:units[i].unitID];

        if([ids containsObject:unitID]) {
            allUnique = NO;
        }

        [ids addObject:unitID];

        // Every unit has a non-empty unitID.
        CHECK(unitID.length > 0, "unit has non-empty unitID");

        // Every non-unconditional unit's prefKey is a real plist key in the
        // shipped defaults (no dangling pref key = dead group).
        if(units[i].prefKey) {
            CHECK(SHDWDefaultHookSettings()[units[i].prefKey] != nil, "unit prefKey exists in shipped defaults");
            CHECK([units[i].prefKey hasPrefix:@"Universal_"] || [units[i].prefKey hasPrefix:@"Adapter_"], "unit prefKey is a canonical domain plist key");
        }
    }

    CHECK(allUnique, "install-unit IDs unique");
}

static void TestCapabilityCoverage(void) {
    NSUInteger count = 0;
    const SHDWInstallUnit* units = SHDWInstallUnits(&count);

    // Every prefKey used by the units resolves to a capability kind string
    // ("message"/"function"/"inline"), so the Settings UI and the
    // coordinator agree on the backend role of every installable group.
    NSMutableSet* seenKeys = [NSMutableSet new];

    for(NSUInteger i = 0; i < count; i++) {
        if(!units[i].prefKey) {
            continue;
        }

        NSString* key = units[i].prefKey;

        if([seenKeys containsObject:key]) {
            continue;   // compound groups share a prefKey (Filesystem@c/@objc)
        }

        [seenKeys addObject:key];
        CHECK(SHDWHookGroupCapabilityKind(key) != nil, "every unit prefKey has a capability kind");
    }

    // The known capability-kind keys are all reachable from the unit table.
    CHECK([seenKeys containsObject:SHDWUniversalDynamicLibrariesExtraID], "dylibex key covered by unit table");
}

static void TestPresetConsistency(void) {
    // Standard preset == the shipped defaults over the hook keys (the
    // "standard" install the UI applies is exactly what the planner sees
    // when no prefs have been touched).
    NSDictionary* defaults = SHDWDefaultHookSettings();
    NSDictionary* standard = SHDWPresetStandard();

    CHECK([defaults[SHDWAdapterDTTJailbreakDetectionID] boolValue], "targeted DTT adapter defaults on");
    CHECK([defaults[SHDWAdapterSafeDeviceID] boolValue], "targeted SafeDevice adapter defaults on");
    CHECK([defaults[SHDWAdapterJailMonkeyID] boolValue], "targeted JailMonkey adapter defaults on");
    CHECK([standard[SHDWAdapterDTTJailbreakDetectionID] boolValue] &&
          [standard[SHDWAdapterSafeDeviceID] boolValue] &&
          [standard[SHDWAdapterJailMonkeyID] boolValue],
          "adapter switches participate in presets");

    for(NSString* key in defaults) {
        if([key hasPrefix:@"Universal_"] || [key hasPrefix:@"Adapter_"]) {
            CHECK([standard[key] isEqual:defaults[key]], "standard preset matches defaults for hook key");
        }
    }

    // Maximum = standard + every dangerous hook flipped on.
    NSDictionary* maximum = SHDWPresetMaximum();
    CHECK([maximum[SHDWUniversalSandboxID] boolValue], "maximum preset: sandbox on");
    CHECK([maximum[SHDWUniversalMemoryID] boolValue], "maximum preset: memory on");
    CHECK([maximum[SHDWUniversalAntiDebuggingID] boolValue], "maximum preset: antidebugging on");
    CHECK([maximum[SHDWUniversalFoundationID] boolValue], "maximum preset: foundation on");
    CHECK([maximum[SHDWAdapterDTTJailbreakDetectionID] boolValue] &&
          [maximum[SHDWAdapterSafeDeviceID] boolValue] &&
          [maximum[SHDWAdapterJailMonkeyID] boolValue],
          "maximum preset: all detector adapters on");

    // The maximum preset's hook keys are a superset of the standard's.
    for(NSString* key in standard) {
        CHECK(maximum[key] != nil, "maximum preset covers every standard hook key");
    }
}

static void TestNoDeadGroups(void) {
    // Every hook group key in the shipped defaults is referenced by at least
    // one install unit (no unit → the key's pref can never install anything).
    NSUInteger count = 0;
    const SHDWInstallUnit* units = SHDWInstallUnits(&count);
    NSMutableSet* unitKeys = [NSMutableSet new];

    for(NSUInteger i = 0; i < count; i++) {
        if(units[i].prefKey) {
            [unitKeys addObject:units[i].prefKey];
        }
    }

    NSDictionary* defaults = SHDWDefaultHookSettings();

    for(NSString* key in defaults) {
        if(![key hasPrefix:@"Universal_"] && ![key hasPrefix:@"Adapter_"]) {
            continue;   // Global_Enabled, HK_Library, ... are
                        // not install units
        }

        CHECK([unitKeys containsObject:key] || SHDWHookGroupCapabilityKind(key) != nil,
              "every domain default is installed directly or consumed by an adapter");
    }
}

static void TestSettingsMigration(void) {
    NSDictionary* legacy = @{
        @"Hook_Filesystem" : @NO,
        SHDWUniversalFilesystemID : @YES,
        @"Hook_DeviceCheck" : @NO,
        SHDWAdapterFreeRASPID : @YES,
        @"PseudoSandboxMode" : @2,
    };
    NSDictionary* migrated = SHDWMigratedHookSettings(legacy);

    CHECK([migrated[SHDWUniversalFilesystemID] boolValue], "migration: canonical universal value wins");
    CHECK(![migrated[SHDWAdapterDeviceCheckID] boolValue], "migration: DeviceCheck fans out to its adapter");
    CHECK([migrated[SHDWAdapterFreeRASPID] boolValue], "migration: canonical FreeRASP value wins");
    CHECK([migrated[SHDWUniversalPseudoSandboxModeID] integerValue] == 2, "migration: universal mode moved");
    CHECK(migrated[@"Hook_Filesystem"] == nil && migrated[@"Hook_DeviceCheck"] == nil &&
          migrated[@"PseudoSandboxMode"] == nil, "migration: legacy keys removed");
}

static int bridgeReplacement;
static int bridgeOriginal;
static NSUInteger bridgeFeatureCalls;

static BOOL BridgePathPredicate(NSString* path) {
    return [path isEqualToString:@"/.adapter-test"];
}

static const void* BridgeDladdrRemapper(const void* address, const void* caller) {
    (void)caller;
    return address == &bridgeReplacement ? &bridgeOriginal : NULL;
}

static void BridgeFeatureInstaller(SHDWHookSession* hooks, const void* imageHeader) {
    (void)hooks;
    bridgeFeatureCalls += imageHeader == &bridgeOriginal;
}

static void TestHookAdapterBridge(void) {
    SHDWSetAdapterPathPredicate(BridgePathPredicate);
    CHECK(SHDWAdapterPathIsHidden(@"/.adapter-test"), "bridge: adapter path predicate is visible to universal hooks");
    CHECK(!SHDWAdapterPathIsHidden(@"/stock"), "bridge: adapter path predicate keeps other paths visible");

    SHDWSetDladdrRemapper(BridgeDladdrRemapper);
    CHECK(SHDWRemapDladdrAddress(&bridgeReplacement, NULL) == &bridgeOriginal,
          "bridge: adapter dladdr remapper is visible to universal hooks");

    SHDWRegisterUniversalFeatureInstaller(SHDWUniversalFeatureSymbolicLinks, BridgeFeatureInstaller);
    SHDWRequestUniversalFeatures(SHDWUniversalFeatureSymbolicLinks, nil, &bridgeOriginal);
    CHECK(bridgeFeatureCalls == 1, "bridge: adapter feature request invokes the registered universal feature");
}

int RunCoordinatorTests(void) {
    cg = 0;
    cf = 0;

    @autoreleasepool {
        TestPlannerCtorOrder();
        TestPlannerGating();
        TestPlannerUIKit();
        TestPlannerEscalation();
        TestPlannerSDKFallback();
        TestInstallUnitConsistency();
        TestCapabilityCoverage();
        TestPresetConsistency();
        TestNoDeadGroups();
        TestSettingsMigration();
        TestHookAdapterBridge();
    }

    printf("CoordinatorTests: %d passed, %d failed\n", cg, cf);

    return cf;
}
