#import <Shadow/Settings.h>

#import "../common.h"
#import <Shadow/JBPath.h>
#import <Shadow/HookConfiguration.h>
#import "SettingsMigration.h"

static NSString* const kSHDWDetectorRunnerOverridesKey = @"Test_DetectorOverrides";

@implementation ShadowSettings
@synthesize defaultSettings, userDefaults;

- (instancetype)init {
    if((self = [super init])) {
        // Enabled apps all receive this one built-in profile. Stored hook
        // values are intentionally ignored — getPreferencesForIdentifier:
        // copies this dictionary directly, so the profile is never read back
        // through userDefaults. Deliberately no registerDefaults: registering
        // the fixed profile would re-materialize every hook key into the
        // persisted plist as a phantom switch and undo the migration prune.
        defaultSettings = SHDWDefaultHookSettings();

        userDefaults = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
        [self migrateLegacyHookSettings];
    }

    return self;
}

- (void)migrateLegacyHookSettings {
    // Read and write the same store. initWithSuiteName: persists through
    // cfprefsd (on rootless, to /var/jb/var/mobile/...), whereas the literal
    // SHADOW_PREFS_PLIST path names a different, stale /var/mobile/... file; a
    // file-sourced snapshot diffs against the wrong store and prunes nothing.
    // persistentDomainForName: returns exactly this suite's stored keys (no
    // global/registration domains), so the rebuild below can never drop a
    // system default.
    NSDictionary* root = [userDefaults persistentDomainForName:@SHADOW_PREFS_PLIST];
    if(![root isKindOfClass:[NSDictionary class]]) {
        return;
    }

    NSDictionary* migratedRoot = SHDWMigratedHookSettings(root);
    BOOL firstSingleToggleMigration = ![root[SHDWSingleToggleMigrationID] boolValue];
    BOOL legacyGlobalEnabled = [root[SHDWGlobalEnabledID] boolValue];

    // Rebuild the migrated domain and write it back wholesale with
    // setPersistentDomain:forName: — a single atomic replace, rather than
    // per-key setObject:/removeObjectForKey: calls whose removals are the
    // unreliable half through the cfprefsd bridge. The result is exactly the
    // pruned shape.
    NSMutableDictionary* domain = [NSMutableDictionary dictionary];
    for(NSString* key in migratedRoot) {
        id value = migratedRoot[key];
        if([value isKindOfClass:[NSDictionary class]]) {
            NSMutableDictionary* migratedApp = [SHDWMigratedHookSettings(value) mutableCopy];
            if(firstSingleToggleMigration && legacyGlobalEnabled &&
               ![value[SHDWAppDisabledID] boolValue] && ![value[SHDWAppEnabledID] boolValue]) {
                migratedApp[SHDWAppEnabledID] = @YES;
            }
            domain[key] = [migratedApp copy];
        } else {
            domain[key] = value;
        }
    }
    if(firstSingleToggleMigration) {
        domain[SHDWSingleToggleMigrationID] = @YES;
    }

    if(![domain isEqualToDictionary:root]) {
        [userDefaults setPersistentDomain:domain forName:@SHADOW_PREFS_PLIST];
        [userDefaults synchronize];
    }
}

+ (instancetype)sharedInstance {
    static ShadowSettings* sharedInstance = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        sharedInstance = [self new];
    });

    return sharedInstance;
}

- (NSDictionary<NSString *, id> *)getPreferencesForIdentifier:(NSString *)bundleIdentifier {
    if(!userDefaults) {
        return nil;
    }

    NSMutableDictionary* result = [defaultSettings mutableCopy];
    BOOL isDetectorRunner = [bundleIdentifier hasPrefix:@"me.jjolano.shadow.test."];
    NSDictionary* app_settings = bundleIdentifier ? [userDefaults objectForKey:bundleIdentifier] : nil;
    NSDictionary* filePreferences = nil;
    NSDictionary* fileAppSettings = nil;
    // Sandboxed cfprefsd can omit another app's dictionary despite libSandy's file grant.
    if(bundleIdentifier) {
        id fileRoot = [NSDictionary dictionaryWithContentsOfFile:@SHADOW_PREFS_PLIST];
        filePreferences = [fileRoot isKindOfClass:[NSDictionary class]] ? fileRoot : nil;
        id fileSettings = filePreferences[bundleIdentifier];
        fileAppSettings = [fileSettings isKindOfClass:[NSDictionary class]] ? SHDWMigratedHookSettings(fileSettings) : nil;
    }
    if(!app_settings) {
        app_settings = fileAppSettings;
    }

    // Test profiles are file-authoritative so cfprefsd cannot retain an old
    // arm while the device driver swaps the backing plist.
    if(([bundleIdentifier isEqualToString:@"me.jjolano.shadow.harness"] || isDetectorRunner) &&
       filePreferences) {
        app_settings = fileAppSettings;
    }

    BOOL enabled = SHDWApplicationEnabled(app_settings,
        [userDefaults boolForKey:SHDWGlobalEnabledID],
        [userDefaults boolForKey:SHDWSingleToggleMigrationID],
        isDetectorRunner || bundleIdentifier.length == 0);
    result[SHDWAppEnabledID] = @(enabled);

    if(enabled) {
        // Not user configuration: the device evidence driver can disable one
        // adapter for an isolated runner without weakening normal app profiles.
        NSDictionary* overrides = isDetectorRunner &&
            [app_settings[kSHDWDetectorRunnerOverridesKey] isKindOfClass:[NSDictionary class]]
            ? app_settings[kSHDWDetectorRunnerOverridesKey] : nil;
        for(NSString* key in @[ SHDWAdapterDeviceCheckID, SHDWAdapterFreeRASPID,
                                SHDWAdapterDeviceSecurityKitID, SHDWAdapterIOSSecuritySuiteID ]) {
            id value = overrides[key];
            if([value isKindOfClass:[NSNumber class]]) {
                result[key] = @([value boolValue]);
            }
        }

        // The isolated IOSSecuritySuite runner dlopens its bridge only after
        // Core's constructor, then invokes this deferred test profile itself.
        if([bundleIdentifier isEqualToString:@"me.jjolano.shadow.test.iossecuritysuite"]) {
            result[SHDWUniversalHarnessBaselineID] = @YES;
        }

        // Harness normally records a universal baseline before SDK-specific
        // hooks load. Its explicit test mode may opt into a fully prearmed
        // detector run without changing any other app's behavior.
        if([bundleIdentifier isEqualToString:@"me.jjolano.shadow.harness"]) {
            id baseline = [app_settings objectForKey:SHDWUniversalHarnessBaselineID];
            if(baseline != nil) {
                result[SHDWUniversalHarnessBaselineID] = baseline;
            }
        }
    }

    return [result copy];
}
@end
