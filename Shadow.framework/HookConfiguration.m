#import <Shadow/HookConfiguration.h>

// Canonical metadata for the hook lifecycle/configuration registry — see
// HookConfiguration.h. Pure Foundation; no behavior on its own.

#pragma mark - Install units

// Canonical ordered install-unit table. Every lifecycle pass walks this order.
static const SHDWInstallUnit kSHDWInstallUnits[] = {
    // Identity concealment — unconditional, installed for every enabled app.
    { "dyld",                 NULL,                          SHDWPhaseAlways,      SHDWCapabilityFunction,    1, 1 },
    { "Hook_Filesystem@c",    SHDWHookIDFilesystem,          SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Hook_EnvVars@c",       SHDWHookIDEnvVars,             SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Hook_EnvVars@objc",    SHDWHookIDEnvVars,             SHDWPhaseTier1,       SHDWCapabilityMessage,     1, 0 },
    { "Hook_DeviceCheck",     SHDWHookIDDeviceCheck,         SHDWPhaseTier1,       SHDWCapabilityMessage,     1, 0 },
    { "Hook_MachBootstrap",   SHDWHookIDMachBootstrap,       SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Hook_IOKit",           SHDWHookIDIOKit,               SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Hook_LowLevelC",       SHDWHookIDLowLevelC,           SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Hook_AntiDebugging",   SHDWHookIDAntiDebugging,       SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "objc",                 NULL,                          SHDWPhaseAlways,      SHDWCapabilityMessage,     1, 0 },
    // method_getImplementation rides the rebind lane (subMain's inline
    // preflight refuses its tiny prologue; see shadowhook_objc_methodimpl).
    { "objc@methodimpl",      NULL,                          SHDWPhaseAlways,      SHDWCapabilityFunction,    1, 0 },
    { "Hook_Syscall",         SHDWHookIDSyscall,             SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Hook_Memory",          SHDWHookIDMemory,              SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Hook_Sandbox",         SHDWHookIDSandbox,             SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "classes",              NULL,                          SHDWPhaseAlways,      SHDWCapabilityMessage,     1, 0 },
    { "symlookup",            NULL,                          SHDWPhaseAlways,      SHDWCapabilitySymlookup,   1, 1 },
    // dlopen_internal: ctor installs it pref-gated; detector escalation
    // installs it unconditionally (the coordinator gates on the backend).
    { "Hook_DynamicLibrariesExtra", SHDWHookIDDynamicLibrariesExtra,
                                                                  SHDWPhaseEscalation, SHDWCapabilityPrivateSym, 1, 1 },
    // Tier-2: ObjC-method swizzles install on first detector evidence.
    { "Hook_Filesystem@objc", SHDWHookIDFilesystem,          SHDWPhaseTier2,       SHDWCapabilityMessage,     0, 0 },
    { "Hook_Foundation@objc", SHDWHookIDFoundation,          SHDWPhaseTier2,       SHDWCapabilityMessage,     0, 0 },
    { "Hook_HideApps",        SHDWHookIDHideApps,            SHDWPhaseTier2,       SHDWCapabilityMessage,     0, 0 },
    // UIKit-load groups (the classes only exist once UIKit is loaded).
    { "Hook_URLScheme",       SHDWHookIDURLScheme,           SHDWPhaseUIKit,       SHDWCapabilityMessage,     0, 0 },
    { "Hook_Foundation@uikit", SHDWHookIDFoundation,         SHDWPhaseUIKit,       SHDWCapabilityMessage,     0, 0 },
};

const SHDWInstallUnit* SHDWInstallUnits(NSUInteger* outCount) {
    if(outCount) {
        *outCount = sizeof(kSHDWInstallUnits) / sizeof(kSHDWInstallUnits[0]);
    }

    return kSHDWInstallUnits;
}

#pragma mark - Defaults and presets

NSDictionary<NSString*, id>* SHDWDefaultHookSettings(void) {
    return @{
        SHDWGlobalEnabledID : @(NO),
        SHDWHookLibraryID : @"auto",
        SHDWHookIDFilesystem : @(YES),
        SHDWHookIDURLScheme : @(YES),
        SHDWHookIDEnvVars : @(YES),
        SHDWHookIDFoundation : @(NO),
        SHDWHookIDDeviceCheck : @(YES),
        SHDWHookIDMachBootstrap : @(NO),
        // C0-4: identity groups (dyld/objc/classes/symlookup) are forced
        // on unconditionally — off-by-default = that vector is 100% exposed
        // on a default install (detectors enumerate the dyld/objc surface
        // before any pref can be flipped). Sandbox, Memory, and
        // AntiDebugging are now ON by default (safe blanket denials);
        // Syscall remains opt-in due to raw svc risk. IOKit and
        // MachBootstrap remain NO (explicit intent; ctor defaulted via
        // missing key before metadata existed).
        SHDWHookIDIOKit : @(NO),
        SHDWHookIDLowLevelC : @(YES),
        SHDWHookIDAntiDebugging : @(YES),
        SHDWHookIDDynamicLibrariesExtra : @(NO),
        SHDWHookIDSyscall : @(NO),
        SHDWHookIDSandbox : @(YES),
        SHDWHookIDMemory : @(YES),
        SHDWHookIDHideApps : @(YES),
        SHDWPseudoSandboxModeID : @(0),
        // PathRewrite: natural-ENOENT path-buffer rewrite (svc trampoline +
        // libc hooks). Default OFF — the rewrite munges the caller's path
        // buffer in place (propagation win, but the munged string is visible
        // to the app's own logging/UI).
        SHDWPathRewriteID : @(NO),
        // AR2 emergency kill-switch: the dyld_all_image_infos memory-hiding
        // patch is unconditional by default (untrusted callers read the raw
        // struct), but a misbehaving patch on a new iOS must be disableable
        // without a reinstall. Default YES (patch on); flipping to NO
        // restores dyld's original struct and stops the patch — detection
        // exposure returns, crashes stop.
        SHDWMemoryLevelHidingID : @(YES)
    };
}

// Hook keys only — the subset of defaults the presets steer (every
// Hook_* toggle plus PseudoSandboxMode; not Global_Enabled / HK_Library /
// MemoryLevelHiding / App_Enabled).
static NSArray<NSString*>* SHDWPresetKeys(void) {
    static NSArray<NSString*>* keys = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSMutableArray* mutableKeys = [NSMutableArray new];

        for(NSString* key in SHDWDefaultHookSettings()) {
            if([key hasPrefix:@"Hook_"] || [key isEqualToString:SHDWPseudoSandboxModeID]) {
                [mutableKeys addObject:key];
            }
        }

        keys = [mutableKeys copy];
    });

    return keys;
}

NSDictionary<NSString*, id>* SHDWPresetStandard(void) {
    // "standard" derives from the shipped defaults — one source of truth,
    // so a defaults change can never drift from the default preset.
    NSDictionary<NSString*, id>* defaults = SHDWDefaultHookSettings();
    NSMutableDictionary* preset = [NSMutableDictionary new];

    for(NSString* key in SHDWPresetKeys()) {
        preset[key] = defaults[key];
    }

    return preset;
}

NSDictionary<NSString*, id>* SHDWPresetMaximum(void) {
    // "maximum": standard plus every dangerous hook — the blanket denial
    // groups that break legitimate apps, and the detector-evidence groups.
    NSDictionary<NSString*, id>* standard = SHDWPresetStandard();
    NSMutableDictionary* preset = [standard mutableCopy];

    preset[SHDWHookIDFoundation] = @(YES);
    preset[SHDWHookIDMachBootstrap] = @(YES);
    preset[SHDWHookIDIOKit] = @(YES);
    preset[SHDWHookIDAntiDebugging] = @(YES);
    preset[SHDWHookIDDynamicLibrariesExtra] = @(YES);
    preset[SHDWHookIDSyscall] = @(YES);
    preset[SHDWHookIDSandbox] = @(YES);
    preset[SHDWHookIDMemory] = @(YES);
    preset[SHDWPathRewriteID] = @(YES);

    return preset;
}

#pragma mark - Capability metadata

NSString* SHDWHookGroupCapabilityKind(NSString* groupID) {
    static NSDictionary<NSString*, NSString*>* kinds = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        kinds = @{
            // ObjC-method swizzle groups (subMain): the Settings picker
            // filters substrate/substitute/swift out of selection, so these
            // need a message-capable backend.
            SHDWHookIDURLScheme : @"message",
            SHDWHookIDDeviceCheck : @"message",  // descriptor-driven ObjC-method installs
            SHDWHookIDFoundation : @"message",   // NSArray/NSBundle/... + UIImage
            SHDWHookIDHideApps : @"message",     // LSApplicationWorkspace
            // dlopen_internal is a private libdyld symbol: needs ElleKit
            // (inline / private-symbol capable).
            SHDWHookIDDynamicLibrariesExtra : @"inline",
            // C-function groups: any non-Swift backend can run them.
            // EnvVars' core (libc env filtering) rides the C-function lane;
            // its NSProcessInfo swizzles are a subMain add-on that fail-softs
            // without a message backend — gate the group on the C path.
            SHDWHookIDEnvVars : @"function",
            SHDWHookIDFilesystem : @"function",
            SHDWHookIDMachBootstrap : @"function",
            SHDWHookIDIOKit : @"function",
            SHDWHookIDLowLevelC : @"function",
            SHDWHookIDAntiDebugging : @"function",
            SHDWHookIDSyscall : @"function",
            SHDWHookIDSandbox : @"function",
            SHDWHookIDMemory : @"function",
            // Pseudo sandbox: policy inside RestrictionEngine, pref-driven, not an
            // install unit — no backend requirement (keeps diff minimal).
            SHDWPseudoSandboxModeID : @"none",
            // Removed as inert; accepted-but-ignored stale key.
            SHDWStaleFakeMacID : @"none",
        };
    });

    return kinds[groupID];
}

#pragma mark - Planner

static BOOL SHDWUnitEnabled(const SHDWInstallUnit* unit,
                            NSDictionary<NSString*, id>* prefs,
                            SHDWLifecycleEvent event) {
    if(!unit->prefKey) {
        return YES;  // unconditional (identity concealment)
    }

    // dylibex: escalation installs it whether or not the pref is on (the
    // coordinator gates on the resolved private-symbol backend).
    if(event == SHDWEventDetectorEscalation && unit->phase == SHDWPhaseEscalation) {
        return YES;
    }

    return [prefs[unit->prefKey] boolValue];
}

// ObjC-message groups require a message backend. dlopen_internal is gated by
// the coordinator because its private-symbol backend is resolved there.
static BOOL SHDWUnitCapable(const SHDWInstallUnit* unit, SHDWCapabilities caps) {
    if(unit->phase == SHDWPhaseEscalation) {
        // dlopen_internal's backend gate and skip log live in the coordinator.
        return YES;
    }

    if(unit->capability != SHDWCapabilityMessage) {
        return YES;
    }

    // objc, classes, tier-2 ObjC groups and the UIKit groups all fail-soft
    // without a message-capable backend.
    return (caps & SHDWCapMessage) != 0;
}

NSArray<NSString*>* SHDWHookPlan(NSDictionary<NSString*, id>* prefs,
                                 SHDWCapabilities caps,
                                 SHDWLifecycleEvent event) {
    NSDictionary<NSString*, id>* effective = prefs ?: SHDWDefaultHookSettings();
    NSMutableArray<NSString*>* plan = [NSMutableArray new];

    NSUInteger count = 0;
    const SHDWInstallUnit* units = SHDWInstallUnits(&count);

    for(NSUInteger i = 0; i < count; i++) {
        const SHDWInstallUnit* unit = &units[i];
        BOOL include = NO;

        switch(event) {
            case SHDWEventCtor:
                include = unit->ctorInstall != 0;
                break;
            case SHDWEventUIKitLoaded:
                include = unit->phase == SHDWPhaseUIKit;
                break;
            case SHDWEventDetectorEscalation:
                include = unit->phase == SHDWPhaseTier2 || unit->phase == SHDWPhaseEscalation;
                break;
        }

        if(!include) {
            continue;
        }

        if(!SHDWUnitEnabled(unit, effective, event)) {
            continue;
        }

        if(!SHDWUnitCapable(unit, caps)) {
            continue;
        }

        [plan addObject:[NSString stringWithUTF8String:unit->unitID]];
    }

    return plan;
}
