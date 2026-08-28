#import <Shadow/HookConfiguration.h>
#import <Shadow/SHDWPluginOrder.inc>

// Canonical metadata for the hook lifecycle/configuration registry — see
// SHDWPlugin.h. Pure Foundation; no behavior on its own.
// Hybrid seam: kSHDWPlugins is the renamed kSHDWInstallUnits (alias kept).

#pragma mark - Plugin registry (renamed InstallUnits)

// Canonical ordered plugin table. Every lifecycle pass walks this order.
// Hybrid: order verified against SHDWPluginOrder.inc at compile time.
static const SHDWPlugin kSHDWPlugins[] = {
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
    // Code-signing self-validation concealment: rebind-lane C hooks on the
    // Security.framework validity surface (own-executable failures only).
    { "Hook_CodeSigning",     SHDWHookIDCodeSigning,         SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
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
    // Generic detector integrity: reveal pre-Shadow IMPs and protect only
    // import slots Shadow actually rebound. Installed on detector evidence.
    { "detector-integrity",    NULL,                          SHDWPhaseTier2,       SHDWCapabilityFunction,    0, 0 },
    // Tier-2: ObjC-method swizzles install on first detector evidence.
    { "Hook_Filesystem@objc", SHDWHookIDFilesystem,          SHDWPhaseTier2,       SHDWCapabilityMessage,     0, 0 },
    { "Hook_Foundation@objc", SHDWHookIDFoundation,          SHDWPhaseTier2,       SHDWCapabilityMessage,     0, 0 },
    { "Hook_HideApps",        SHDWHookIDHideApps,            SHDWPhaseTier2,       SHDWCapabilityMessage,     0, 0 },
    // UIKit-load groups (the classes only exist once UIKit is loaded).
    { "Hook_URLScheme",       SHDWHookIDURLScheme,           SHDWPhaseUIKit,       SHDWCapabilityMessage,     0, 0 },
    { "Hook_Foundation@uikit", SHDWHookIDFoundation,         SHDWPhaseUIKit,       SHDWCapabilityMessage,     0, 0 },
    // Policy plugins — evaluated via RestrictionEngine / policy/*.m, not via
    // HookCoordinator install. Registered here so SHDWPluginRegistry is the
    // single source for hook+policy metadata. Never installed via HookPlan
    // (ctorInstall 0). Pref gating lives in policy code, not planner.
    { "Policy_Path",          NULL,                          SHDWPhaseAlways,      SHDWCapabilityNone,        0, 0 },
    { "Policy_Environment",   NULL,                          SHDWPhaseAlways,      SHDWCapabilityNone,        0, 0 },
    { "Policy_Process",       NULL,                          SHDWPhaseAlways,      SHDWCapabilityNone,        0, 0 },
    { "Policy_PseudoSandbox", NULL,                          SHDWPhaseAlways,      SHDWCapabilityNone,        0, 0 },
};

// Hybrid verification: plugin count must match canonical order
static const char* const kSHDWPluginOrderCheck[] __attribute__((unused)) = { SHDW_PLUGIN_ORDER };
_Static_assert(sizeof(kSHDWPlugins)/sizeof(kSHDWPlugins[0]) == sizeof(kSHDWPluginOrderCheck)/sizeof(kSHDWPluginOrderCheck[0]), "plugin registry drift vs SHDWPluginOrder.inc — edit order.inc, not tables");
_Static_assert(sizeof(kSHDWPlugins)/sizeof(kSHDWPlugins[0]) == SHDW_PLUGIN_COUNT, "plugin count != SHDW_PLUGIN_COUNT");

const SHDWPlugin* SHDWPluginRegistry(NSUInteger* outCount) {
    if(outCount) {
        *outCount = sizeof(kSHDWPlugins) / sizeof(kSHDWPlugins[0]);
    }
    return kSHDWPlugins;
}

const SHDWInstallUnit* SHDWInstallUnits(NSUInteger* outCount) {
    // Compat shim — same storage, new name
    if(outCount) {
        *outCount = sizeof(kSHDWPlugins) / sizeof(kSHDWPlugins[0]);
    }
    return (const SHDWInstallUnit*)kSHDWPlugins;
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
        SHDWHookIDIOKit : @(NO),
        SHDWHookIDLowLevelC : @(YES),
        SHDWHookIDAntiDebugging : @(YES),
        SHDWHookIDCodeSigning : @(YES),
        SHDWHookIDDynamicLibrariesExtra : @(NO),
        SHDWHookIDSyscall : @(NO),
        SHDWHookIDSandbox : @(YES),
        SHDWHookIDMemory : @(YES),
        SHDWHookIDHideApps : @(YES),
        SHDWPseudoSandboxModeID : @(0),
        SHDWPathRewriteID : @(NO),
        SHDWDetectorPatchDTTID : @(YES),
        SHDWDetectorPatchSafeDeviceID : @(YES),
        SHDWDetectorPatchJailMonkeyID : @(YES),
        SHDWDetectorPatchIOSSecuritySuiteID : @(YES),
        SHDWDetectorPatchFreeRASPID : @(YES),
        SHDWMemoryLevelHidingID : @(YES)
    };
}

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
    NSDictionary<NSString*, id>* defaults = SHDWDefaultHookSettings();
    NSMutableDictionary* preset = [NSMutableDictionary new];
    for(NSString* key in SHDWPresetKeys()) {
        preset[key] = defaults[key];
    }
    return preset;
}

NSDictionary<NSString*, id>* SHDWPresetMaximum(void) {
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
    preset[SHDWDetectorPatchDTTID] = @(YES);
    preset[SHDWDetectorPatchSafeDeviceID] = @(YES);
    preset[SHDWDetectorPatchJailMonkeyID] = @(YES);
    preset[SHDWDetectorPatchIOSSecuritySuiteID] = @(YES);
    preset[SHDWDetectorPatchFreeRASPID] = @(YES);
    return preset;
}

#pragma mark - Capability metadata

NSString* SHDWHookGroupCapabilityKind(NSString* groupID) {
    static NSDictionary<NSString*, NSString*>* kinds = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        kinds = @{
            SHDWHookIDURLScheme : @"message",
            SHDWHookIDDeviceCheck : @"message",
            SHDWHookIDFoundation : @"message",
            SHDWHookIDHideApps : @"message",
            SHDWHookIDDynamicLibrariesExtra : @"inline",
            SHDWHookIDEnvVars : @"function",
            SHDWHookIDFilesystem : @"function",
            SHDWHookIDMachBootstrap : @"function",
            SHDWHookIDIOKit : @"function",
            SHDWHookIDLowLevelC : @"function",
            SHDWHookIDAntiDebugging : @"function",
            SHDWHookIDCodeSigning : @"function",
            SHDWHookIDSyscall : @"function",
            SHDWHookIDSandbox : @"function",
            SHDWHookIDMemory : @"function",
            SHDWPseudoSandboxModeID : @"none",
        };
    });
    return kinds[groupID];
}

#pragma mark - Planner

static BOOL SHDWPluginEnabled(const SHDWPlugin* plugin,
                             NSDictionary<NSString*, id>* prefs,
                             SHDWLifecycleEvent event) {
    if(!plugin->prefKey) {
        return YES;
    }
    if(event == SHDWEventDetectorEscalation && plugin->phase == SHDWPhaseEscalation) {
        return YES;
    }
    return [prefs[plugin->prefKey] boolValue];
}

static BOOL SHDWPluginCapable(const SHDWPlugin* plugin, SHDWCapabilities caps) {
    if(plugin->phase == SHDWPhaseEscalation) {
        return YES;
    }
    if(plugin->capability != SHDWCapabilityMessage) {
        return YES;
    }
    return (caps & SHDWCapMessage) != 0;
}

NSArray<NSString*>* SHDWPluginPlan(NSDictionary<NSString*, id>* prefs,
                                  SHDWCapabilities caps,
                                  SHDWLifecycleEvent event) {
    NSDictionary<NSString*, id>* effective = prefs ?: SHDWDefaultHookSettings();
    NSMutableArray<NSString*>* plan = [NSMutableArray new];
    NSUInteger count = 0;
    const SHDWPlugin* plugins = SHDWPluginRegistry(&count);
    for(NSUInteger i = 0; i < count; i++) {
        const SHDWPlugin* plugin = &plugins[i];
        BOOL include = NO;
        switch(event) {
            case SHDWEventCtor:
                include = plugin->ctorInstall != 0;
                break;
            case SHDWEventUIKitLoaded:
                include = plugin->phase == SHDWPhaseUIKit;
                break;
            case SHDWEventDetectorEscalation:
                include = plugin->phase == SHDWPhaseTier2 || plugin->phase == SHDWPhaseEscalation;
                break;
        }
        if(!include) continue;
        if(!SHDWPluginEnabled(plugin, effective, event)) continue;
        if(!SHDWPluginCapable(plugin, caps)) continue;
        [plan addObject:[NSString stringWithUTF8String:plugin->unitID]];
    }
    return plan;
}

// Compat shims — forward to new planner
NSArray<NSString*>* SHDWHookPlan(NSDictionary<NSString*, id>* prefs,
                                 SHDWCapabilities caps,
                                 SHDWLifecycleEvent event) {
    return SHDWPluginPlan(prefs, caps, event);
}

// Legacy internal helpers kept for compat
static BOOL SHDWUnitEnabled(const SHDWInstallUnit* unit, NSDictionary<NSString*, id>* prefs, SHDWLifecycleEvent event) __attribute__((unused));
static BOOL SHDWUnitEnabled(const SHDWInstallUnit* unit, NSDictionary<NSString*, id>* prefs, SHDWLifecycleEvent event) {
    return SHDWPluginEnabled((const SHDWPlugin*)unit, prefs, event);
}
static BOOL SHDWUnitCapable(const SHDWInstallUnit* unit, SHDWCapabilities caps) __attribute__((unused));
static BOOL SHDWUnitCapable(const SHDWInstallUnit* unit, SHDWCapabilities caps) {
    return SHDWPluginCapable((const SHDWPlugin*)unit, caps);
}
