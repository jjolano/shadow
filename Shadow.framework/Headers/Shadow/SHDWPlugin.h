#ifndef shadow_plugin_h
#define shadow_plugin_h

#import <Foundation/Foundation.h>

// Canonical plugin registry — single source of truth for hook/policy
// lifecycle, defaults, presets and planner. Pure Foundation; safe to link
// from any binary and from the host test harness.
// Hybrid seam: SHDWPlugin is the renamed SHDWInstallUnit (type alias kept
// for compat), SHDWPluginRegistry is the renamed SHDWInstallUnits.

#if defined(__GNUC__) && (__GNUC__ >= 4)
#define SHDW_EXPORT __attribute__((visibility("default")))
#else
#define SHDW_EXPORT
#endif

#pragma mark - Hook IDs (plist preference keys)

#define SHDWUniversalFilesystemID             @"Universal_Filesystem"
#define SHDWUniversalURLSchemeID              @"Universal_URLScheme"
#define SHDWUniversalEnvVarsID                @"Universal_EnvVars"
#define SHDWUniversalFoundationID             @"Universal_Foundation"
#define SHDWUniversalMachBootstrapID          @"Universal_MachBootstrap"
#define SHDWUniversalIOKitID                  @"Universal_IOKit"
#define SHDWUniversalLowLevelCID              @"Universal_LowLevelC"
#define SHDWUniversalAntiDebuggingID          @"Universal_AntiDebugging"
#define SHDWUniversalCodeSigningID            @"Universal_CodeSigning"
#define SHDWUniversalDynamicLibrariesExtraID  @"Universal_DynamicLibrariesExtra"
#define SHDWUniversalSyscallID                @"Universal_Syscall"
#define SHDWUniversalSandboxID                @"Universal_Sandbox"
#define SHDWUniversalMemoryID                 @"Universal_Memory"
#define SHDWUniversalHideAppsID               @"Universal_HideApps"
#define SHDWUniversalPseudoSandboxModeID      @"Universal_PseudoSandboxMode"
#define SHDWUniversalPathRewriteID            @"Universal_PathRewrite"
#define SHDWUniversalMemoryLevelHidingID      @"Universal_MemoryLevelHiding"
#define SHDWUniversalHarnessBaselineID        @"Universal_HarnessBaseline"

#define SHDWAdapterDeviceCheckID              @"Adapter_DeviceCheck"
#define SHDWAdapterFreeRASPID                 @"Adapter_FreeRASP"
#define SHDWAdapterDeviceSecurityKitID        @"Adapter_DeviceSecurityKit"
#define SHDWAdapterIOSSecuritySuiteID         @"Adapter_IOSSecuritySuite"
#define SHDWAdapterDTTJailbreakDetectionID    @"Adapter_DTTJailbreakDetection"
#define SHDWAdapterSafeDeviceID               @"Adapter_SafeDevice"
#define SHDWAdapterJailMonkeyID               @"Adapter_JailMonkey"

#define SHDWGlobalEnabledID        @"Global_Enabled"
#define SHDWHookLibraryID          @"HK_Library"
#define SHDWAppEnabledID           @"App_Enabled"
#define SHDWAppDisabledID          @"App_Disabled"

#pragma mark - Lifecycle phases

typedef NS_ENUM(NSInteger, SHDWLifecyclePhase) {
    SHDWPhaseAlways = 0,
    SHDWPhaseTier1,
    SHDWPhaseTier2,
    SHDWPhaseUIKit,
    SHDWPhaseEscalation,
    SHDWPhaseSDKFallback,
};

typedef NS_ENUM(NSInteger, SHDWLifecycleEvent) {
    SHDWEventCtor = 0,
    SHDWEventUIKitLoaded,
    SHDWEventDetectorEscalation,
    SHDWEventSDKFallback,
};

#pragma mark - Native HookKit request capabilities

typedef NS_OPTIONS(NSUInteger, SHDWCapabilities) {
    SHDWCapMessage   = 1 << 0,
    SHDWCapFunction  = 1 << 1,
    SHDWCapInline    = 1 << 2,
    SHDWCapPrivateSym = 1 << 3,
};

#pragma mark - Plugin (renamed InstallUnit)

typedef NS_ENUM(NSInteger, SHDWCapabilityKind) {
    SHDWCapabilityNone = 0,
    SHDWCapabilityMessage,
    SHDWCapabilityFunction,
    SHDWCapabilitySymlookup,
    SHDWCapabilityPrivateSym,
};

// One installable plugin = one installer call with one backend role.
// Renamed from SHDWInstallUnit; pluginID is canonical, unitID is compat alias via macro.
typedef struct {
    const char* pluginID;
    NSString* prefKey;
    SHDWLifecyclePhase phase;
    SHDWCapabilityKind capability;
    unsigned ctorInstall : 1;
    unsigned verify : 1;
} SHDWPlugin;
#ifndef unitID
#define unitID pluginID
#endif

// Backward-compat alias — single source, no duplication.
typedef SHDWPlugin SHDWInstallUnit;

#pragma mark - Registry (renamed InstallUnits)

SHDW_EXPORT const SHDWPlugin* SHDWPluginRegistry(NSUInteger* outCount);
// Compat: old name forwards to new impl
SHDW_EXPORT const SHDWInstallUnit* SHDWInstallUnits(NSUInteger* outCount);

#pragma mark - Defaults and presets

SHDW_EXPORT NSDictionary<NSString*, id>* SHDWDefaultHookSettings(void);
SHDW_EXPORT NSDictionary<NSString*, id>* SHDWPresetStandard(void);
SHDW_EXPORT NSDictionary<NSString*, id>* SHDWPresetMaximum(void);

#pragma mark - Capability metadata

SHDW_EXPORT NSString* SHDWHookGroupCapabilityKind(NSString* groupID);

#pragma mark - Planner (pure)

SHDW_EXPORT NSArray<NSString*>* SHDWPluginPlan(NSDictionary<NSString*, id>* prefs,
                                               SHDWCapabilities caps,
                                               SHDWLifecycleEvent event);
// Compat
SHDW_EXPORT NSArray<NSString*>* SHDWHookPlan(NSDictionary<NSString*, id>* prefs,
                                             SHDWCapabilities caps,
                                             SHDWLifecycleEvent event);

#endif // shadow_plugin_h
