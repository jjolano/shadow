#import "AdapterHooks.h"
#import "DeviceCheckHooks.h"

// Opt-in adapter.
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
