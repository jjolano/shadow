#import "AdapterHooks.h"
#import "DeviceCheckHooks.h"

// Opt-in adapter.
static DCHTarget s_enabledTargets = DCHTargetDTT | DCHTargetSafeDevice | DCHTargetJailMonkey;
void shdw_adapter_devicecheck_configure(NSDictionary* prefs) {
    s_enabledTargets = DCHTargetNone;
    for(NSUInteger i = 0; i < kSHDWDeviceCheckTargetCount; i++) {
        if([prefs[kSHDWDeviceCheckTargets[i].prefKey] boolValue]) {
            s_enabledTargets |= kSHDWDeviceCheckTargets[i].target;
        }
    }
}

void shdw_adapter_devicecheck(SHDWHookSession* hooks) {
    shdw_devicecheck_install_hooks(hooks, s_enabledTargets);
}
