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
        // values are intentionally ignored.
        defaultSettings = SHDWDefaultHookSettings();

        userDefaults = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
        [self migrateLegacyHookSettings];
        [userDefaults registerDefaults:defaultSettings];
    }

    return self;
}

- (void)migrateLegacyHookSettings {
    NSDictionary* root = [NSDictionary dictionaryWithContentsOfFile:@SHADOW_PREFS_PLIST];
    if(![root isKindOfClass:[NSDictionary class]]) {
        return;
    }

    NSDictionary* migratedRoot = SHDWMigratedHookSettings(root);
    BOOL firstSingleToggleMigration = ![root[SHDWSingleToggleMigrationID] boolValue];
    BOOL legacyGlobalEnabled = [root[SHDWGlobalEnabledID] boolValue];
    BOOL changed = NO;
    for(NSString* key in migratedRoot) {
        id value = migratedRoot[key];
        if([value isKindOfClass:[NSDictionary class]]) {
            NSMutableDictionary* migratedApp = [SHDWMigratedHookSettings(value) mutableCopy];
            if(firstSingleToggleMigration && legacyGlobalEnabled &&
               ![value[SHDWAppDisabledID] boolValue] && ![value[SHDWAppEnabledID] boolValue]) {
                migratedApp[SHDWAppEnabledID] = @YES;
            }
            if(![migratedApp isEqual:value]) {
                [userDefaults setObject:[migratedApp copy] forKey:key];
                changed = YES;
            }
        } else if(![value isEqual:root[key]]) {
            [userDefaults setObject:value forKey:key];
            changed = YES;
        }
    }
    for(NSString* key in root) {
        if(![root[key] isKindOfClass:[NSDictionary class]] && !migratedRoot[key]) {
            [userDefaults removeObjectForKey:key];
            changed = YES;
        }
    }
    if(firstSingleToggleMigration) {
        [userDefaults setBool:YES forKey:SHDWSingleToggleMigrationID];
        changed = YES;
    }
    if(changed) {
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
