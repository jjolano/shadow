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

#define SHDWHookIDFilesystem       @"Hook_Filesystem"
#define SHDWHookIDURLScheme        @"Hook_URLScheme"
#define SHDWHookIDEnvVars          @"Hook_EnvVars"
#define SHDWHookIDDeviceCheck      @"Hook_DeviceCheck"
#define SHDWHookIDFoundation       @"Hook_Foundation"
#define SHDWHookIDMachBootstrap    @"Hook_MachBootstrap"
#define SHDWHookIDIOKit            @"Hook_IOKit"
#define SHDWHookIDLowLevelC        @"Hook_LowLevelC"
#define SHDWHookIDAntiDebugging    @"Hook_AntiDebugging"
#define SHDWHookIDCodeSigning      @"Hook_CodeSigning"
#define SHDWHookIDDynamicLibrariesExtra @"Hook_DynamicLibrariesExtra"
#define SHDWHookIDSyscall          @"Hook_Syscall"
#define SHDWHookIDSandbox          @"Hook_Sandbox"
#define SHDWHookIDMemory           @"Hook_Memory"
#define SHDWHookIDHideApps         @"Hook_HideApps"
#define SHDWPseudoSandboxModeID    @"PseudoSandboxMode"
#define SHDWPathRewriteID          @"PathRewrite"

#define SHDWDetectorPatchDTTID        @"DetectorPatch_DTTJailbreakDetection"
#define SHDWDetectorPatchSafeDeviceID @"DetectorPatch_SafeDevice"
#define SHDWDetectorPatchJailMonkeyID @"DetectorPatch_JailMonkey"

#define SHDWGlobalEnabledID        @"Global_Enabled"
#define SHDWHookLibraryID          @"HK_Library"
#define SHDWMemoryLevelHidingID    @"MemoryLevelHiding"
#define SHDWAppEnabledID           @"App_Enabled"
#define SHDWAppDisabledID          @"App_Disabled"

#pragma mark - Lifecycle phases

typedef NS_ENUM(NSInteger, SHDWLifecyclePhase) {
    SHDWPhaseAlways = 0,
    SHDWPhaseTier1,
    SHDWPhaseTier2,
    SHDWPhaseUIKit,
    SHDWPhaseEscalation,
};

typedef NS_ENUM(NSInteger, SHDWLifecycleEvent) {
    SHDWEventCtor = 0,
    SHDWEventUIKitLoaded,
    SHDWEventDetectorEscalation,
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
