#ifndef shadow_capabilities_h
#define shadow_capabilities_h

#import <Foundation/Foundation.h>

// Runtime capability checks for the Settings UI. Two sources of truth:
//   - HKSubstitutor availability (which hooking backends exist on device)
//   - the shadowd daemon's krw state (via SHADOWD_OP_STATUS)
// Controllers call SHDWApplyHookGroupGating: on their loaded specifiers to
// disable toggles whose backend is missing, with a footer note explaining why.

// Daemon health, as reported by shadowd's STATUS op.
typedef NS_ENUM(NSInteger, SHDWDaemonState) {
    SHDWDaemonUnavailable = 0,  // service not registered / no reply
    SHDWDaemonStarting,         // krw init in progress
    SHDWDaemonDisabled,         // krw failed or version-gated off
    SHDWDaemonReady,
};

// Query daemon krw state via Mach IPC (bootstrap_look_up + STATUS). Returns
// the cached value immediately; the first call triggers a background refresh
// (see SHDWRefreshDaemonStateAsync:) so the Settings UI never blocks on IPC.
SHDWDaemonState SHDWQueryDaemonState(void);

// Refresh the daemon state on a background queue; completion runs on the main
// queue with the fresh state. Callers re-apply gating on receipt.
void SHDWRefreshDaemonStateAsync(void (^completion)(SHDWDaemonState state));

// Hook-group capability matrix. groupID is the plist id (e.g. "Hook_Memory").
// Supported = the selected/available backends can actually run the group's
// hooks. Mirrors the backend routing in ShadowCore.dylib/dylib.x.
BOOL SHDWHookGroupSupported(NSString* groupID);

// Localized footer reason for an unsupported group, or nil if supported.
NSString* SHDWHookGroupUnsupportedReason(NSString* groupID);

// Iterate loaded specifiers; disable unsupported toggle cells and append the
// reason to the enclosing group's footerText. Safe on any specifier array
// (App/Hooks/Dangerous plists).
void SHDWApplyHookGroupGating(NSArray* specifiers);

#endif
