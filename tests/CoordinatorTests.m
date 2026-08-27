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
    prefs[SHDWHookIDFilesystem] = @(YES);
    prefs[SHDWHookIDURLScheme] = @(YES);
    prefs[SHDWHookIDEnvVars] = @(YES);
    prefs[SHDWHookIDFoundation] = @(YES);
    prefs[SHDWHookIDDeviceCheck] = @(YES);
    prefs[SHDWHookIDMachBootstrap] = @(YES);
    prefs[SHDWHookIDIOKit] = @(YES);
    prefs[SHDWHookIDLowLevelC] = @(YES);
    prefs[SHDWHookIDAntiDebugging] = @(YES);
    prefs[SHDWHookIDCodeSigning] = @(YES);
    prefs[SHDWHookIDDynamicLibrariesExtra] = @(YES);
    prefs[SHDWHookIDSyscall] = @(YES);
    prefs[SHDWHookIDSandbox] = @(YES);
    prefs[SHDWHookIDMemory] = @(YES);
    prefs[SHDWHookIDHideApps] = @(YES);
    return prefs;
}

// The exact expected ctor order: canonical table order, restricted to
// ctorInstall units.
static NSArray* ExpectedCtorOrder(void) {
    return @[
        @"dyld",
        @"Hook_Filesystem@c",
        @"Hook_EnvVars@c",
        @"Hook_EnvVars@objc",
        @"Hook_DeviceCheck",
        @"Hook_MachBootstrap",
        @"Hook_IOKit",
        @"Hook_LowLevelC",
        @"Hook_AntiDebugging",
        @"Hook_CodeSigning",
        @"objc",
        @"objc@methodimpl",
        @"Hook_Syscall",
        @"Hook_Memory",
        @"Hook_Sandbox",
        @"classes",
        @"symlookup",
        @"Hook_DynamicLibrariesExtra",
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
    CHECK(!IDInPlan(plan, "objc"), "no message backend: 'objc' fail-soft dropped");
    CHECK(!IDInPlan(plan, "classes"), "no message backend: 'classes' fail-soft dropped");
    CHECK(!IDInPlan(plan, "Hook_EnvVars@objc"), "no message backend: EnvVars@objc fail-soft dropped");
    CHECK(IDInPlan(plan, "Hook_EnvVars@c"), "no message backend: EnvVars@c (function) still installs");
    CHECK(IDInPlan(plan, "dyld"), "no message backend: 'dyld' (identity) still installs");
    CHECK(IDInPlan(plan, "symlookup"), "no message backend: 'symlookup' still installs");

    // Full caps: the same units are present again.
    NSArray* planFull = SHDWHookPlan(AllOnPrefs(), full, SHDWEventCtor);
    CHECK(IDInPlan(planFull, "objc"), "message backend present: 'objc' installs");
    CHECK(IDInPlan(planFull, "classes"), "message backend present: 'classes' installs");

    // Pref-off: gated units leave the plan; identity units stay.
    NSDictionary* prefs = DefaultsFor(SHDWHookIDFilesystem, NO);
    NSArray* planOff = SHDWHookPlan(prefs, full, SHDWEventCtor);
    CHECK(!IDInPlan(planOff, "Hook_Filesystem@c"), "pref off: Hook_Filesystem@c dropped");
    CHECK(IDInPlan(planOff, "dyld"), "pref off: 'dyld' (identity) still installs");
}

static void TestPlannerUIKit(void) {
    SHDWCapabilities full = SHDWCapMessage | SHDWCapFunction | SHDWCapInline | SHDWCapPrivateSym;

    NSArray* plan = SHDWHookPlan(AllOnPrefs(), full, SHDWEventUIKitLoaded);
    CHECK(([plan isEqualToArray:@[ @"Hook_URLScheme", @"Hook_Foundation@uikit" ]]), "uikit plan == the two UIKit-class units, in order");

    // Message backend required by the UIKit groups.
    NSArray* planFish = SHDWHookPlan(AllOnPrefs(), SHDWCapFunction, SHDWEventUIKitLoaded);
    CHECK(planFish.count == 0, "no message backend: uikit plan empty");

    // Pref-gated.
    NSDictionary* prefs = DefaultsFor(SHDWHookIDURLScheme, NO);
    NSArray* planPref = SHDWHookPlan(prefs, full, SHDWEventUIKitLoaded);
    CHECK(!IDInPlan(planPref, "Hook_URLScheme"), "uikit: URLScheme pref off → dropped");
    CHECK(!IDInPlan(planPref, "Hook_Foundation@uikit"), "uikit: Foundation default off → dropped");

    NSDictionary* prefsFnd = DefaultsFor(SHDWHookIDFoundation, YES);
    NSArray* planFnd = SHDWHookPlan(prefsFnd, full, SHDWEventUIKitLoaded);
    CHECK(IDInPlan(planFnd, "Hook_Foundation@uikit"), "uikit: Foundation pref on → present");
}

static void TestPlannerEscalation(void) {
    SHDWCapabilities full = SHDWCapMessage | SHDWCapFunction | SHDWCapInline | SHDWCapPrivateSym;

    // Canonical escalation order: dylibex first, then tier-2 units in
    // table order (mirrors shdw_detector_detected: dyldextra then tier-2).
    NSArray* plan = SHDWHookPlan(AllOnPrefs(), full, SHDWEventDetectorEscalation);
    NSArray* expected = @[
        @"Hook_DynamicLibrariesExtra",
        @"Hook_Filesystem@objc",
        @"Hook_Foundation@objc",
        @"Hook_HideApps",
    ];

    CHECK([plan isEqualToArray:expected], "escalation plan == dylibex first, tier-2 in canonical order");

    // dylibex installs even with the pref off (coordinator gates on backend).
    NSDictionary* prefs = DefaultsFor(SHDWHookIDDynamicLibrariesExtra, NO);
    NSArray* planPref = SHDWHookPlan(prefs, full, SHDWEventDetectorEscalation);
    CHECK(IDInPlan(planPref, "Hook_DynamicLibrariesExtra"), "escalation: dylibex unconditional (backend-gated, not pref-gated)");

    // Idempotence: repeated calls return equal plans (no state).
    CHECK([plan isEqualToArray:SHDWHookPlan(AllOnPrefs(), full, SHDWEventDetectorEscalation)], "escalation plan idempotent");

    // No message backend: tier-2 ObjC units drop, dylibex stays (its
    // capability gate lives in the coordinator).
    NSArray* planFish = SHDWHookPlan(AllOnPrefs(), SHDWCapFunction, SHDWEventDetectorEscalation);
    CHECK(IDInPlan(planFish, "Hook_DynamicLibrariesExtra"), "fishhook-only: dylibex still named (coordinator gates it)");
    CHECK(!IDInPlan(planFish, "Hook_Filesystem@objc"), "fishhook-only: tier-2 ObjC dropped");
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
            CHECK([units[i].prefKey hasPrefix:@"Hook_"], "unit prefKey is a canonical Hook_ plist key");
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
    CHECK([seenKeys containsObject:SHDWHookIDDynamicLibrariesExtra], "dylibex key covered by unit table");
}

static void TestPresetConsistency(void) {
    // Standard preset == the shipped defaults over the hook keys (the
    // "standard" install the UI applies is exactly what the planner sees
    // when no prefs have been touched).
    NSDictionary* defaults = SHDWDefaultHookSettings();
    NSDictionary* standard = SHDWPresetStandard();

    CHECK(![defaults[SHDWDetectorPatchDTTID] boolValue], "targeted DTT patch defaults off");
    CHECK(![defaults[SHDWDetectorPatchSafeDeviceID] boolValue], "targeted SafeDevice patch defaults off");
    CHECK(![defaults[SHDWDetectorPatchJailMonkeyID] boolValue], "targeted JailMonkey patch defaults off");
    CHECK(![defaults[SHDWDetectorPatchIOSSecuritySuiteID] boolValue], "targeted IOSSecuritySuite patch defaults off");
    CHECK(![defaults[SHDWDetectorPatchFreeRASPID] boolValue], "targeted freeRASP patch defaults off");
    CHECK(standard[SHDWDetectorPatchDTTID] == nil &&
          standard[SHDWDetectorPatchSafeDeviceID] == nil &&
          standard[SHDWDetectorPatchJailMonkeyID] == nil &&
          standard[SHDWDetectorPatchIOSSecuritySuiteID] == nil &&
          standard[SHDWDetectorPatchFreeRASPID] == nil,
          "targeted detector patches stay outside hook presets");

    for(NSString* key in defaults) {
        if([key hasPrefix:@"Hook_"]) {
            CHECK([standard[key] isEqual:defaults[key]], "standard preset matches defaults for hook key");
        }
    }

    // Maximum = standard + every dangerous hook flipped on.
    NSDictionary* maximum = SHDWPresetMaximum();
    CHECK([maximum[SHDWHookIDSandbox] boolValue], "maximum preset: sandbox on");
    CHECK([maximum[SHDWHookIDMemory] boolValue], "maximum preset: memory on");
    CHECK([maximum[SHDWHookIDAntiDebugging] boolValue], "maximum preset: antidebugging on");
    CHECK([maximum[SHDWHookIDFoundation] boolValue], "maximum preset: foundation on");

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
        if(![key hasPrefix:@"Hook_"]) {
            continue;   // Global_Enabled, HK_Library, ... are
                        // not install units
        }

        CHECK([unitKeys containsObject:key], "every defaults Hook_ key is covered by an install unit");
    }
}

int RunCoordinatorTests(void) {
    cg = 0;
    cf = 0;

    @autoreleasepool {
        TestPlannerCtorOrder();
        TestPlannerGating();
        TestPlannerUIKit();
        TestPlannerEscalation();
        TestInstallUnitConsistency();
        TestCapabilityCoverage();
        TestPresetConsistency();
        TestNoDeadGroups();
    }

    printf("CoordinatorTests: %d passed, %d failed\n", cg, cf);

    return cf;
}
