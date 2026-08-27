#import "hooks.h"
#import "DeviceCheckHooks.h"

// Opt-in (Hook_DeviceCheck): attestation fails closed — apps that require
// DeviceCheck attestation see "unsupported" and must fall back to their
// degraded path instead of minting real attestation artifacts.
// TODO: DCDevice generateToken/generateKey and DCAppAttestService
// generateKey/attestKey/generateAssertion are deliberately NOT hooked — the
// artifacts are server-verifiable, so a forged value would fail attestation
// on the server side; returning "unsupported" here is the only honest answer.
//
// Step 2: every %hook block migrated to the descriptor table in
// DeviceCheckHooks.m (batches 1-6). This file is now a thin install call:
// the descriptor-driven install (shdw_devicecheck_install_hooks) walks the
// table, resolves each class/method's runtime encoding, and swaps in the
// matching replacement IMP via the passed message-capable hook session.
// Late-loaded detector-class retry needs the dylib.x watcher wiring (not
// implemented here).

// Encoding-aware install for third-party rooted/jailbroken properties whose
// return ABI varies between SDK versions (descriptor-driven): the runtime
// method encoding is inspected at install — B@:/c@: → BOOL-returning hook
// (NO), @@: → object-returning hook (nil), anything else → skip and leave
// the real method untouched.

static DCHTarget s_enabledTargets = DCHTargetNone;

// Public API imported by the tested freeRASP 6.4.0 app. Rebinding the lazy
// import avoids an inline prologue patch; the replacement returns Void and
// safely ignores its Swift config argument on arm64.
static void shdw_freerasp_start_disabled(void) {}
static NSString* const kSHDWFreeRASPStartSymbol = @"$s13TalsecRuntime0A0C5start6configyAA0A6ConfigV_tFZ";

void shadowhook_DeviceCheck_configure(NSDictionary* prefs) {
    s_enabledTargets = DCHTargetNone;

    if([prefs[SHDWDetectorPatchDTTID] boolValue]) {
        s_enabledTargets |= DCHTargetDTT;
    }
    if([prefs[SHDWDetectorPatchSafeDeviceID] boolValue]) {
        s_enabledTargets |= DCHTargetSafeDevice;
    }
    if([prefs[SHDWDetectorPatchJailMonkeyID] boolValue]) {
        s_enabledTargets |= DCHTargetJailMonkey;
    }
    if([prefs[SHDWDetectorPatchFreeRASPID] boolValue]) {
        s_enabledTargets |= DCHTargetFreeRASP;
    }
}

void shadowhook_DeviceCheck(SHDWHookSession* hooks) {
    shdw_devicecheck_install_hooks(hooks, s_enabledTargets);

    if(s_enabledTargets & DCHTargetFreeRASP) {
        [hooks hookRebindSymbol:kSHDWFreeRASPStartSymbol
                withReplacement:(void*)shdw_freerasp_start_disabled
                       outOldPtr:NULL];
    }
}
