#import "AdapterHooks.h"
#import "DeviceCheckHooks.h"

// Opt-in adapter: attestation fails closed — apps that require
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

static DCHTarget s_enabledTargets = DCHTargetDTT | DCHTargetSafeDevice | DCHTargetJailMonkey;
void shdw_adapter_devicecheck_configure(NSDictionary* prefs) {
    s_enabledTargets = DCHTargetNone;
    if([prefs[SHDWAdapterDTTJailbreakDetectionID] boolValue]) {
        s_enabledTargets |= DCHTargetDTT;
    }
    if([prefs[SHDWAdapterSafeDeviceID] boolValue]) {
        s_enabledTargets |= DCHTargetSafeDevice;
    }
    if([prefs[SHDWAdapterJailMonkeyID] boolValue]) {
        s_enabledTargets |= DCHTargetJailMonkey;
    }
}

void shdw_adapter_devicecheck(SHDWHookSession* hooks) {
    shdw_devicecheck_install_hooks(hooks, s_enabledTargets);
}
