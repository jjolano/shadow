#import "SettingsMigration.h"

#import <Shadow/SHDWPlugin.h>

NSDictionary<NSString*, id>* SHDWMigratedHookSettings(NSDictionary<NSString*, id>* settings) {
    NSMutableDictionary<NSString*, id>* migrated = [settings mutableCopy] ?: [NSMutableDictionary new];

    // App_Disabled used to override App_Enabled. The single-toggle model
    // expresses the same state directly and never writes App_Disabled again.
    if([settings[SHDWAppDisabledID] boolValue]) {
        migrated[SHDWAppEnabledID] = @NO;
    }
    [migrated removeObjectForKey:SHDWAppDisabledID];

    NSArray<NSArray<NSString*>*>* mappings = @[
        @[ @"Hook_Filesystem", SHDWUniversalFilesystemID ],
        @[ @"Hook_URLScheme", SHDWUniversalURLSchemeID ],
        @[ @"Hook_EnvVars", SHDWUniversalEnvVarsID ],
        @[ @"Hook_Foundation", SHDWUniversalFoundationID ],
        @[ @"Hook_MachBootstrap", SHDWUniversalMachBootstrapID ],
        @[ @"Hook_IOKit", SHDWUniversalIOKitID ],
        @[ @"Hook_LowLevelC", SHDWUniversalLowLevelCID ],
        @[ @"Hook_AntiDebugging", SHDWUniversalAntiDebuggingID ],
        @[ @"Hook_CodeSigning", SHDWUniversalCodeSigningID ],
        @[ @"Hook_DynamicLibrariesExtra", SHDWUniversalDynamicLibrariesExtraID ],
        @[ @"Hook_Syscall", SHDWUniversalSyscallID ],
        @[ @"Hook_Sandbox", SHDWUniversalSandboxID ],
        @[ @"Hook_Memory", SHDWUniversalMemoryID ],
        @[ @"Hook_HideApps", SHDWUniversalHideAppsID ],
        @[ @"PseudoSandboxMode", SHDWUniversalPseudoSandboxModeID ],
        @[ @"PathRewrite", SHDWUniversalPathRewriteID ],
        @[ @"MemoryLevelHiding", SHDWUniversalMemoryLevelHidingID ],
        @[ @"DetectorPatch_DTTJailbreakDetection", SHDWAdapterDTTJailbreakDetectionID ],
        @[ @"DetectorPatch_SafeDevice", SHDWAdapterSafeDeviceID ],
        @[ @"DetectorPatch_JailMonkey", SHDWAdapterJailMonkeyID ],
        @[ @"HarnessUniversalBaseline", SHDWUniversalHarnessBaselineID ],
    ];

    for(NSArray<NSString*>* mapping in mappings) {
        NSString* legacy = mapping[0];
        NSString* canonical = mapping[1];
        id value = settings[legacy];
        if(value && !migrated[canonical]) {
            migrated[canonical] = value;
        }
        [migrated removeObjectForKey:legacy];
    }

    id deviceCheck = settings[@"Hook_DeviceCheck"];
    if(deviceCheck) {
        if(!migrated[SHDWAdapterDeviceCheckID]) {
            migrated[SHDWAdapterDeviceCheckID] = deviceCheck;
        }
        if(!migrated[SHDWAdapterFreeRASPID]) {
            migrated[SHDWAdapterFreeRASPID] = deviceCheck;
        }
    }
    [migrated removeObjectForKey:@"Hook_DeviceCheck"];

    return [migrated copy];
}
