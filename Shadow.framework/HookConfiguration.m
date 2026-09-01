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
    { "Universal_Dyld",                 NULL,                                  SHDWPhaseAlways,      SHDWCapabilityFunction,    1, 1 },
    { "Universal_Filesystem_C",         SHDWUniversalFilesystemID,             SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Universal_EnvVars_C",            SHDWUniversalEnvVarsID,                SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Universal_EnvVars_ObjC",         SHDWUniversalEnvVarsID,                SHDWPhaseTier1,       SHDWCapabilityMessage,     1, 0 },
    { "Adapter_DeviceCheck",            SHDWAdapterDeviceCheckID,              SHDWPhaseSDKFallback, SHDWCapabilityMessage,     1, 0 },
    { "Adapter_FreeRASP",               SHDWAdapterFreeRASPID,                 SHDWPhaseAlways,      SHDWCapabilityFunction,    1, 0 },
    { "Universal_MachBootstrap",        SHDWUniversalMachBootstrapID,          SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Universal_IOKit",                SHDWUniversalIOKitID,                  SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Universal_LowLevelC",            SHDWUniversalLowLevelCID,              SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Universal_AntiDebugging",        SHDWUniversalAntiDebuggingID,          SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    // Code-signing self-validation concealment: rebind-lane C hooks on the
    // Security.framework validity surface (own-executable failures only).
    { "Universal_CodeSigning",          SHDWUniversalCodeSigningID,            SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Universal_ObjC",                 NULL,                                  SHDWPhaseAlways,      SHDWCapabilityMessage,     1, 0 },
    // method_getImplementation rides the rebind lane (subMain's inline
    // preflight refuses its tiny prologue; see shadowhook_objc_methodimpl).
    { "Universal_ObjC_MethodImplementation", NULL,                           SHDWPhaseAlways,      SHDWCapabilityFunction,    1, 0 },
    { "Universal_Syscall",              SHDWUniversalSyscallID,                SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Universal_Memory",               SHDWUniversalMemoryID,                 SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Universal_Sandbox",              SHDWUniversalSandboxID,                SHDWPhaseTier1,       SHDWCapabilityFunction,    1, 1 },
    { "Universal_HideClasses",          NULL,                                  SHDWPhaseAlways,      SHDWCapabilityMessage,     1, 0 },
    { "Universal_SymbolLookup",         NULL,                                  SHDWPhaseAlways,      SHDWCapabilitySymlookup,   1, 1 },
    // dlopen_internal: ctor installs it pref-gated; detector escalation
    // installs it unconditionally (the coordinator gates on the backend).
    { "Universal_DynamicLibrariesExtra", SHDWUniversalDynamicLibrariesExtraID,
                                                                  SHDWPhaseEscalation, SHDWCapabilityPrivateSym, 1, 1 },
    // Generic detector integrity: reveal pre-Shadow IMPs and protect only
    // import slots Shadow actually rebound. Installed on detector evidence.
    { "Universal_DetectorIntegrity",   NULL,                                  SHDWPhaseTier2,       SHDWCapabilityFunction,    0, 0 },
    // Tier-2: ObjC-method swizzles install on first detector evidence.
    { "Universal_Filesystem_ObjC",     SHDWUniversalFilesystemID,             SHDWPhaseTier2,       SHDWCapabilityMessage,     0, 0 },
    { "Universal_Foundation_ObjC",     SHDWUniversalFoundationID,             SHDWPhaseTier2,       SHDWCapabilityMessage,     0, 0 },
    { "Universal_HideApps",            SHDWUniversalHideAppsID,               SHDWPhaseTier2,       SHDWCapabilityMessage,     0, 0 },
    // UIKit-load groups (the classes only exist once UIKit is loaded).
    { "Universal_URLScheme",          SHDWUniversalURLSchemeID,              SHDWPhaseUIKit,       SHDWCapabilityMessage,     0, 0 },
    { "Universal_Foundation_UIKit",   SHDWUniversalFoundationID,             SHDWPhaseUIKit,       SHDWCapabilityMessage,     0, 0 },
    { "Adapter_DeviceSecurityKit",    SHDWAdapterDeviceSecurityKitID,        SHDWPhaseSDKFallback, SHDWCapabilityMessage,     1, 0 },
    { "Adapter_IOSSecuritySuite",     SHDWAdapterIOSSecuritySuiteID,         SHDWPhaseSDKFallback, SHDWCapabilityFunction,    1, 0 },
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

#pragma mark - Built-in profile

NSDictionary<NSString*, id>* SHDWDefaultHookSettings(void) {
    return @{
        SHDWHookLibraryID : @"auto",
        SHDWUniversalFilesystemID : @(YES),
        SHDWUniversalURLSchemeID : @(YES),
        SHDWUniversalEnvVarsID : @(YES),
        SHDWUniversalFoundationID : @(YES),
        SHDWUniversalMachBootstrapID : @(YES),
        SHDWUniversalIOKitID : @(YES),
        SHDWUniversalLowLevelCID : @(YES),
        SHDWUniversalAntiDebuggingID : @(YES),
        SHDWUniversalCodeSigningID : @(YES),
        SHDWUniversalDynamicLibrariesExtraID : @(YES),
        SHDWUniversalSyscallID : @(YES),
        SHDWUniversalSandboxID : @(YES),
        SHDWUniversalMemoryID : @(YES),
        SHDWUniversalHideAppsID : @(YES),
        SHDWUniversalPseudoSandboxModeID : @(0),
        SHDWUniversalPathRewriteID : @(YES),
        SHDWUniversalMemoryLevelHidingID : @(YES),
        SHDWAdapterDeviceCheckID : @(YES),
        SHDWAdapterFreeRASPID : @(YES),
        SHDWAdapterDeviceSecurityKitID : @(YES),
        SHDWAdapterIOSSecuritySuiteID : @(YES),
        SHDWAdapterDTTJailbreakDetectionID : @(YES),
        SHDWAdapterSafeDeviceID : @(YES),
        SHDWAdapterJailMonkeyID : @(YES)
    };
}

#pragma mark - Capability metadata

NSString* SHDWHookGroupCapabilityKind(NSString* groupID) {
    static NSDictionary<NSString*, NSString*>* kinds = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        kinds = @{
            SHDWUniversalURLSchemeID : @"message",
            SHDWUniversalFoundationID : @"message",
            SHDWUniversalHideAppsID : @"message",
            SHDWUniversalDynamicLibrariesExtraID : @"inline",
            SHDWUniversalEnvVarsID : @"function",
            SHDWUniversalFilesystemID : @"function",
            SHDWUniversalMachBootstrapID : @"function",
            SHDWUniversalIOKitID : @"function",
            SHDWUniversalLowLevelCID : @"function",
            SHDWUniversalAntiDebuggingID : @"function",
            SHDWUniversalCodeSigningID : @"function",
            SHDWUniversalSyscallID : @"function",
            SHDWUniversalSandboxID : @"function",
            SHDWUniversalMemoryID : @"function",
            SHDWUniversalPseudoSandboxModeID : @"none",
            SHDWUniversalPathRewriteID : @"none",
            SHDWUniversalMemoryLevelHidingID : @"none",
            SHDWAdapterDeviceCheckID : @"message",
            SHDWAdapterFreeRASPID : @"function",
            SHDWAdapterDeviceSecurityKitID : @"message",
            SHDWAdapterIOSSecuritySuiteID : @"function",
            SHDWAdapterDTTJailbreakDetectionID : @"message",
            SHDWAdapterSafeDeviceID : @"message",
            SHDWAdapterJailMonkeyID : @"message",
        };
    });
    return kinds[groupID];
}

#pragma mark - Planner

static BOOL SHDWPluginEnabled(const SHDWPlugin* plugin,
                              NSDictionary<NSString*, id>* prefs,
                              SHDWLifecycleEvent event) {
    // Harness frameworks load per detector. Both baseline and prearmed test
    // modes defer target-dependent adapters until that first pass has loaded
    // every target; production apps have no Harness profile key and
    // retain their early adapter behavior.
    if(plugin->phase == SHDWPhaseSDKFallback && event == SHDWEventCtor &&
       prefs[SHDWUniversalHarnessBaselineID] != nil) {
        return NO;
    }
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
            case SHDWEventSDKFallback:
                include = plugin->phase == SHDWPhaseSDKFallback;
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
