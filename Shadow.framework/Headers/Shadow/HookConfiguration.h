#ifndef shadow_hook_configuration_h
#define shadow_hook_configuration_h

#import <Foundation/Foundation.h>

// Canonical hook-group metadata for Shadow's lifecycle/configuration
// registry. Single source of truth for hook IDs, shipped defaults, presets,
// backend-capability kinds and lifecycle phases — replacing the scattered,
// drifting copies in Settings.m / SHDWHooksListController /
// SHDWCapabilities / dylib.x.
//
// Pure Foundation: safe to compile into any binary that links the framework,
// and safe to compile into the host test harness unchanged.

#if defined(__GNUC__) && (__GNUC__ >= 4)
#define SHDW_EXPORT __attribute__((visibility("default")))
#else
#define SHDW_EXPORT
#endif

#pragma mark - Hook IDs (plist preference keys)

// Canonical hook IDs. These are the plist preference keys the Settings UI
// toggles and the lifecycle coordinator gates on.
#define SHDWHookIDFilesystem       @"Hook_Filesystem"
#define SHDWHookIDURLScheme        @"Hook_URLScheme"
#define SHDWHookIDEnvVars          @"Hook_EnvVars"
#define SHDWHookIDDeviceCheck      @"Hook_DeviceCheck"
#define SHDWHookIDFoundation       @"Hook_Foundation"
#define SHDWHookIDMachBootstrap    @"Hook_MachBootstrap"
#define SHDWHookIDIOKit            @"Hook_IOKit"
#define SHDWHookIDLowLevelC        @"Hook_LowLevelC"
#define SHDWHookIDAntiDebugging    @"Hook_AntiDebugging"
#define SHDWHookIDDynamicLibrariesExtra @"Hook_DynamicLibrariesExtra"
#define SHDWHookIDSyscall          @"Hook_Syscall"
#define SHDWHookIDSandbox          @"Hook_Sandbox"
#define SHDWHookIDMemory           @"Hook_Memory"
#define SHDWHookIDHideApps         @"Hook_HideApps"
#define SHDWVnodeHidingID          @"VnodeHiding"
#define SHDWPseudoSandboxModeID    @"PseudoSandboxMode"
#define SHDWPathRewriteID          @"PathRewrite"

// Non-hook preferences (kept for completeness; not hook groups).
#define SHDWGlobalEnabledID        @"Global_Enabled"
#define SHDWHookLibraryID          @"HK_Library"
#define SHDWMemoryLevelHidingID    @"MemoryLevelHiding"
#define SHDWAppEnabledID           @"App_Enabled"
// Per-app kill switch: excludes one app from Shadow entirely, overriding
// Global_Enabled. NOT the inverse of App_Enabled — that key means "this app
// has per-app overrides", so its NO state is "follow global", not "off".
#define SHDWAppDisabledID          @"App_Disabled"

// Stale key from older releases: the FakeMac group was removed as inert (its
// installer installs nothing — answering isMacCatalystApp/isiOSAppOnMac YES
// is a universal fingerprint). The key is ACCEPTED but IGNORED: it is not in
// the defaults, presets, capability list or install-unit table, so existing
// preference files that still carry it keep parsing without breaking.
#define SHDWStaleFakeMacID         @"Hook_FakeMac"

#pragma mark - Lifecycle phases

// When an install unit is installed:
//   always     — ctor, unconditional (identity-concealment groups)
//   tier1      — ctor, preference-gated C-function groups
//   tier2      — first detector escalation, pref-gated ObjC-method groups
//   uikit      — UIKit framework load (image watcher), pref-gated classes
//   escalation — detector escalation (dlopen_internal group)
typedef NS_ENUM(NSInteger, SHDWLifecyclePhase) {
    SHDWPhaseAlways = 0,
    SHDWPhaseTier1,
    SHDWPhaseTier2,
    SHDWPhaseUIKit,
    SHDWPhaseEscalation,
};

// Lifecycle events the planner is asked about.
typedef NS_ENUM(NSInteger, SHDWLifecycleEvent) {
    SHDWEventCtor = 0,             // process spawn, after prefs + backends resolved
    SHDWEventUIKitLoaded,          // UIKit framework image loaded
    SHDWEventDetectorEscalation,   // behavioral tripwire fired
};

#pragma mark - Available-backend capabilities (what HKSubstitutor can do)

typedef NS_OPTIONS(NSUInteger, SHDWCapabilities) {
    SHDWCapMessage   = 1 << 0,   // ObjC message swizzle backend (ElleKit/Substrate/Substitute/native)
    SHDWCapFunction  = 1 << 1,   // C-function rebind backend (fishhook etc.)
    SHDWCapInline    = 1 << 2,   // function-inline backend
    SHDWCapPrivateSym = 1 << 3,  // private-symbol-capable backend
};

#pragma mark - Install units

typedef NS_ENUM(NSInteger, SHDWCapabilityKind) {
    SHDWCapabilityNone = 0,     // identity group, no backend requirement
    SHDWCapabilityMessage,      // ObjC-method swizzle (subMain)
    SHDWCapabilityFunction,     // C-function rebind (subCFunc)
    SHDWCapabilitySymlookup,    // inline-first, rebind fallback (dlsym/dladdr pair)
    SHDWCapabilityPrivateSym,   // private-symbol-capable backend (dlopen_internal)
};

// One installable unit = one installer call with one backend role. Compound
// preferences are multiple rows (filesystem-C at tier-1, filesystem-ObjC at
// tier-2) rather than hiding phase differences inside an installer.
typedef struct {
    const char* unitID;             // stable ID, e.g. "Hook_Filesystem@c"
    NSString* prefKey;              // plist key; nil = unconditional group
    SHDWLifecyclePhase phase;       // install timing (see above)
    SHDWCapabilityKind capability;  // backend role for the coordinator
    unsigned ctorInstall : 1;       // installed during the ctor pass
    unsigned verify : 1;            // has a verify function the ctor runs
} SHDWInstallUnit;

// Canonical ordered install-unit table.
// The ctor pass walks this array in order and installs every unit whose
// ctorInstall flag is set and whose prefKey (if any) is enabled.
SHDW_EXPORT const SHDWInstallUnit* SHDWInstallUnits(NSUInteger* outCount);

#pragma mark - Defaults and presets

// Canonical shipped defaults (replaces the inline dictionary in Settings.m).
// Adds the explicit Hook_IOKit = NO default; drops the inert FakeMac key.
SHDW_EXPORT NSDictionary<NSString*, id>* SHDWDefaultHookSettings(void);

// "standard" preset — derives from the shipped defaults (hook keys only).
SHDW_EXPORT NSDictionary<NSString*, id>* SHDWPresetStandard(void);

// "maximum" preset — standard plus every dangerous hook.
SHDW_EXPORT NSDictionary<NSString*, id>* SHDWPresetMaximum(void);

#pragma mark - Capability metadata (Settings UI)

// Backend requirement of a hook group, as a stable string:
//   "message", "function", "inline", "daemon" (VnodeHiding), or "none"
// (not a hook group / stale+ignored, e.g. the removed FakeMac).
SHDW_EXPORT NSString* SHDWHookGroupCapabilityKind(NSString* groupID);

#pragma mark - Planner (pure)

// Plan the ordered install-unit IDs for a lifecycle event, given the
// effective preferences and the available backend capabilities. Returns an
// ordered NSArray<NSString*> of install-unit IDs; no state; host-runnable.
//
// Gating rules:
//   - ctor: units with ctorInstall, pref-gated where prefKey != NULL
//   - UIKit load: phase==uikit units, pref-gated, message backend required
//   - detector escalation: dylibex (unconditional, phase==escalation) then
//     the tier-2 units in canonical order, pref-gated, message backend
//     required. dylibex capability gating happens in the coordinator (its
//     private-symbol backend is resolved there).
SHDW_EXPORT NSArray<NSString*>* SHDWHookPlan(NSDictionary<NSString*, id>* prefs,
                                             SHDWCapabilities caps,
                                             SHDWLifecycleEvent event);

#endif // shadow_hook_configuration_h
