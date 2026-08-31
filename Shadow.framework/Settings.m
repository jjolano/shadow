#import <Shadow/Settings.h>

#import "../common.h"
#import <Shadow/JBPath.h>
#import <Shadow/HookConfiguration.h>
#import "SettingsMigration.h"

@implementation ShadowSettings
@synthesize defaultSettings, userDefaults;

- (instancetype)init {
    if((self = [super init])) {
        // Canonical shipped defaults (Shadow/HookConfiguration.h) — the
        // metadata is the single source of truth. Universal_IOKit is explicit NO
        // (previously absent-by-omission).
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
    BOOL changed = NO;
    for(NSString* key in migratedRoot) {
        id value = migratedRoot[key];
        if([value isKindOfClass:[NSDictionary class]]) {
            NSDictionary* migratedApp = SHDWMigratedHookSettings(value);
            if(![migratedApp isEqual:value]) {
                [userDefaults setObject:migratedApp forKey:key];
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
    NSDictionary* app_settings = bundleIdentifier ? [userDefaults objectForKey:bundleIdentifier] : nil;
    NSDictionary* filePreferences = nil;
    NSDictionary* fileAppSettings = nil;
    // Sandboxed cfprefsd can omit another app's dictionary despite libSandy's file grant.
    if(bundleIdentifier) {
        id fileRoot = [NSDictionary dictionaryWithContentsOfFile:@SHADOW_PREFS_PLIST];
        filePreferences = [fileRoot isKindOfClass:[NSDictionary class]] ? fileRoot : nil;
        id fileSettings = filePreferences[bundleIdentifier];
        fileAppSettings = [fileSettings isKindOfClass:[NSDictionary class]] ? fileSettings : nil;
    }
    if(!app_settings) {
        app_settings = fileAppSettings;
    }

    // Profile selection must be file-authoritative for Harness: otherwise
    // deleting an explicit maximum profile can leave cfprefsd's old dictionary
    // active and prevent the normal universal baseline from returning.
    if([bundleIdentifier isEqualToString:@"me.jjolano.shadow.harness"] &&
       filePreferences) {
        app_settings = fileAppSettings;
    }

    // Per-app kill switch. Distinct from App_Enabled, which means "this app has
    // per-app overrides" — its NO state is "follow global", so it cannot say
    // "off". App_Disabled overrides everything including Global_Enabled, and
    // leaves App_Enabled unset, which is what both ctors gate on: an app the
    // user has excluded is never hooked at all.
    if([[app_settings objectForKey:SHDWAppDisabledID] boolValue]) {
        return [result copy];
    }

    BOOL useAppSettings = [[app_settings objectForKey:@"App_Enabled"] boolValue];
    BOOL isDetectorRunner = [bundleIdentifier hasPrefix:@"me.jjolano.shadow.test."];

    if(useAppSettings || [userDefaults boolForKey:@"Global_Enabled"] || isDetectorRunner) {
        // Per-app overrides win; a key the app does not set inherits the
        // global value (matches the settings UI).
        [result setObject:@(YES) forKey:@"App_Enabled"];

        for(NSString* key in defaultSettings) {
            id value = useAppSettings ? [app_settings objectForKey:key] : nil;

            if(!value) {
                value = [userDefaults objectForKey:key];
            }

            // Absent everywhere (a key added by an upgrade, or a Sandy-
            // filtered read): keep the shipped default already in result.
            // setObject:nil here would throw and abort the whole ctor.
            if(value) {
                [result setObject:value forKey:key];
            }
        }

        // Harness normally records a universal baseline before SDK-specific
        // hooks load. Its explicit test profile may opt into a fully prearmed
        // detector run without changing any other app's behavior.
        if([bundleIdentifier isEqualToString:@"me.jjolano.shadow.harness"]) {
            id baseline = [app_settings objectForKey:SHDWUniversalHarnessBaselineID];
            if(baseline != nil) {
                result[SHDWUniversalHarnessBaselineID] = baseline;
            }
        }

        if([bundleIdentifier isEqualToString:@"me.jjolano.shadow.test.dtt"]) {
            result[SHDWAdapterDTTJailbreakDetectionID] = @YES;
        }
    }

    return [result copy];
}
@end
