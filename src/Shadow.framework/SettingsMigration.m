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

    // Shadow runs its fixed full-capability profile whenever an app is enabled;
    // stored hook toggles (Universal_*, Adapter_*, PseudoSandbox*, the legacy
    // Hook_* names, etc.) no longer take effect. Prune the plist down to the
    // live surface so obsolete keys can never linger as phantom switches that
    // reduce capability. Kept scalars are the activation/migration markers and
    // the per-app harness baseline; dict values are preserved untouched — at
    // the root they are per-app override dicts, and inside a per-app dict the
    // Test_DetectorOverrides map (both handled by a separate migration pass).
    static NSSet* liveScalarKeys = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        liveScalarKeys = [NSSet setWithArray:@[
            SHDWGlobalEnabledID, SHDWSingleToggleMigrationID,
            SHDWAppEnabledID, SHDWUniversalHarnessBaselineID,
            // Live at both scopes: the global default (root scalar) and the
            // per-app override (same key inside an app dict).
            SHDWDetectorAggressiveID,
        ]];
    });

    for(NSString* key in [migrated allKeys]) {
        if([migrated[key] isKindOfClass:[NSDictionary class]]) {
            continue;
        }
        if(![liveScalarKeys containsObject:key]) {
            [migrated removeObjectForKey:key];
        }
    }

    return [migrated copy];
}
