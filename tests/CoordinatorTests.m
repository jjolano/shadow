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
//   - built-in profile enables every additive hook group,
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
#import "../src/Shadow.framework/SettingsMigration.h"
#import "../src/ShadowCore.dylib/HookAdapterBridge.h"

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
    CHECK(IDInPlan(planPref, "Universal_Foundation_UIKit"), "uikit: URLScheme does not gate Foundation");

    NSDictionary* prefsFnd = DefaultsFor(SHDWUniversalFoundationID, NO);
    NSArray* planFnd = SHDWHookPlan(prefsFnd, full, SHDWEventUIKitLoaded);
    CHECK(!IDInPlan(planFnd, "Universal_Foundation_UIKit"), "uikit: Foundation pref off → dropped");
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

    NSMutableDictionary* prearmedHarnessPrefs = [AllOnPrefs() mutableCopy];
    prearmedHarnessPrefs[SHDWUniversalHarnessBaselineID] = @NO;
    NSArray* prearmedHarnessCtor = SHDWHookPlan(prearmedHarnessPrefs, full, SHDWEventCtor);
    CHECK(!IDInPlan(prearmedHarnessCtor, "Adapter_DeviceCheck") &&
          !IDInPlan(prearmedHarnessCtor, "Adapter_DeviceSecurityKit") &&
          !IDInPlan(prearmedHarnessCtor, "Adapter_IOSSecuritySuite"),
          "Harness prearmed mode defers target-dependent SDK adapters");

    NSArray* fallback = SHDWHookPlan(harnessPrefs, full, SHDWEventSDKFallback);
    NSArray* expectedFallback = @[
        @"Adapter_DeviceCheck", @"Adapter_DeviceSecurityKit", @"Adapter_IOSSecuritySuite",
    ];
    CHECK([fallback isEqualToArray:expectedFallback], "SDK fallback restores deferred adapters in registry order");
    CHECK([SHDWHookPlan(prearmedHarnessPrefs, full, SHDWEventSDKFallback) isEqualToArray:expectedFallback],
          "Harness prearmed mode installs SDK adapters after detector frameworks load");
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

static void TestComprehensiveProfile(void) {
    NSDictionary* defaults = SHDWDefaultHookSettings();
    NSUInteger count = 0;
    const SHDWPlugin* plugins = SHDWPluginRegistry(&count);

    for(NSUInteger i = 0; i < count; i++) {
        if(plugins[i].prefKey) {
            CHECK([defaults[plugins[i].prefKey] boolValue], "built-in profile enables every additive hook group");
        }
    }

    CHECK(![defaults[SHDWUniversalPseudoSandboxModeID] boolValue], "built-in profile leaves alternate pseudo-sandbox mode off");
    CHECK([defaults[SHDWUniversalPathRewriteID] boolValue], "built-in profile enables path rewriting");
    CHECK([defaults[SHDWUniversalMemoryLevelHidingID] boolValue], "built-in profile enables memory hiding");
    CHECK([defaults[SHDWAdapterDTTJailbreakDetectionID] boolValue] &&
          [defaults[SHDWAdapterSafeDeviceID] boolValue] &&
          [defaults[SHDWAdapterJailMonkeyID] boolValue],
          "built-in profile enables descriptor-backed detector adapters");
    CHECK([defaults[SHDWHookLibraryID] isEqual:@"auto"], "built-in profile uses automatic hook routing");
    CHECK(defaults[SHDWGlobalEnabledID] == nil && defaults[SHDWAppEnabledID] == nil,
          "activation state is not part of the hook profile");
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
            continue;   // HK_Library is not an install unit
                        // not install units
        }

        CHECK([unitKeys containsObject:key] || SHDWHookGroupCapabilityKind(key) != nil,
              "every domain default is installed directly or consumed by an adapter");
    }
}

static void TestSettingsMigration(void) {
    // Shadow runs its fixed full-capability profile when enabled; stored hook
    // toggles no longer take effect, so migration prunes the plist down to the
    // live surface (activation/migration markers, per-app dicts, harness
    // baseline) and strips everything else so no obsolete key lingers as a
    // phantom switch.
    NSDictionary* legacy = @{
        @"Hook_Filesystem" : @NO,
        SHDWUniversalFilesystemID : @YES,
        @"Hook_DeviceCheck" : @NO,
        SHDWAdapterFreeRASPID : @YES,
        @"PseudoSandboxMode" : @2,
        @"MemoryLevelHiding" : @NO,
        @"PseudoSandboxEnabled" : @YES,
        @"DetectorLog" : @[ @"stale" ],
        @"CrashCount.com.example" : @3,
        SHDWAppEnabledID : @YES,
        SHDWAppDisabledID : @YES,
    };
    NSDictionary* migrated = SHDWMigratedHookSettings(legacy);

    CHECK(![migrated[SHDWAppEnabledID] boolValue] && migrated[SHDWAppDisabledID] == nil,
          "migration: App_Disabled becomes App_Enabled=NO");
    CHECK(migrated[SHDWUniversalFilesystemID] == nil && migrated[SHDWAdapterFreeRASPID] == nil &&
          migrated[SHDWUniversalPseudoSandboxModeID] == nil && migrated[SHDWUniversalMemoryLevelHidingID] == nil,
          "migration: obsolete hook/adapter toggles are pruned");
    CHECK(migrated[@"Hook_Filesystem"] == nil && migrated[@"Hook_DeviceCheck"] == nil &&
          migrated[@"PseudoSandboxMode"] == nil && migrated[@"MemoryLevelHiding"] == nil &&
          migrated[@"PseudoSandboxEnabled"] == nil && migrated[@"DetectorLog"] == nil &&
          migrated[@"CrashCount.com.example"] == nil,
          "migration: legacy and residue keys removed");

    // Live keys survive: activation markers, the per-app harness baseline, and
    // the test-only detector-override dict.
    NSDictionary* live = SHDWMigratedHookSettings(@{
        SHDWGlobalEnabledID : @YES,
        SHDWSingleToggleMigrationID : @YES,
        SHDWAppEnabledID : @YES,
        SHDWUniversalHarnessBaselineID : @YES,
        @"Test_DetectorOverrides" : @{ SHDWAdapterFreeRASPID : @NO },
        @"Universal_Sandbox" : @NO,
    });
    CHECK([live[SHDWGlobalEnabledID] boolValue] && [live[SHDWSingleToggleMigrationID] boolValue] &&
          [live[SHDWAppEnabledID] boolValue] && [live[SHDWUniversalHarnessBaselineID] boolValue],
          "migration: live activation and harness keys are preserved");
    CHECK([live[@"Test_DetectorOverrides"] isKindOfClass:[NSDictionary class]] &&
          live[@"Universal_Sandbox"] == nil,
          "migration: test-override dict kept, stray hook scalar pruned");
}

static void TestApplicationEnabled(void) {
    CHECK(SHDWApplicationEnabled(@{ SHDWAppEnabledID : @NO }, YES, NO, NO),
          "activation: old App_Enabled=NO follows legacy global before migration");
    CHECK(!SHDWApplicationEnabled(@{ SHDWAppEnabledID : @NO }, YES, YES, NO),
          "activation: migrated App_Enabled=NO overrides legacy global");
    CHECK(!SHDWApplicationEnabled(@{ SHDWAppEnabledID : @YES, SHDWAppDisabledID : @YES }, YES, NO, NO),
          "activation: legacy App_Disabled remains off");
    CHECK(SHDWApplicationEnabled(@{ SHDWAppDisabledID : @YES }, NO, YES, YES),
          "activation: verification runner force-enable wins");
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
        TestComprehensiveProfile();
        TestNoDeadGroups();
        TestSettingsMigration();
        TestApplicationEnabled();
        TestHookAdapterBridge();
    }

    printf("CoordinatorTests: %d passed, %d failed\n", cg, cf);

    return cf;
}
