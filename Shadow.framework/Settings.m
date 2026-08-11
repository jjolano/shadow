#import <Shadow/Settings.h>

#import "../common.h"
#import <Shadow/JBPath.h>
#import <Shadow/HookConfiguration.h>

// Preferences schema version. The suite plist never had a version key of its
// own; this stamps it once per install and runs forward migrations below.
// Migrations must stay idempotent and cheap — ShadowSettings is touched by
// the settings app, ShadowCore in every hooked process, and the harness.
static const NSInteger SHDWPrefsSchemaVersion = 1;

@implementation ShadowSettings
@synthesize defaultSettings, userDefaults;

- (instancetype)init {
    if((self = [super init])) {
        // Canonical shipped defaults (Shadow/HookConfiguration.h) — the
        // metadata is the single source of truth. Hook_IOKit is explicit NO
        // (previously absent-by-omission); the stale Hook_FakeMac key is
        // dropped (accepted-but-ignored for legacy preference files).
        defaultSettings = SHDWDefaultHookSettings();

        userDefaults = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
        [userDefaults registerDefaults:defaultSettings];
        [self migratePrefsIfNeeded];
    }

    return self;
}

// Runs the one-time forward migrations between stored schema versions.
- (void)migratePrefsIfNeeded {
    if([userDefaults integerForKey:@"PrefsSchemaVersion"] >= SHDWPrefsSchemaVersion) {
        return;
    }

    [self purgeIgnoredKeys];

    [userDefaults setInteger:SHDWPrefsSchemaVersion forKey:@"PrefsSchemaVersion"];
    [userDefaults synchronize];
}

// Legacy keys the current schema accepts-but-ignores. Purging them is
// cosmetic but keeps the suite clean and stops a stale stored value from
// shadowing a future semantic change to the same key.
- (void)purgeIgnoredKeys {
    NSArray* ignored = @[ @"Hook_FakeMac" ];

    for(NSString* key in ignored) {
        if([userDefaults objectForKey:key]) {
            [userDefaults removeObjectForKey:key];
        }
    }

    // Same cleanup inside per-app override dicts (keyed by bundle ID).
    NSDictionary* representation = [userDefaults dictionaryRepresentation];
    for(NSString* key in representation) {
        id value = representation[key];
        if(![value isKindOfClass:[NSDictionary class]]) {
            continue;
        }

        NSMutableDictionary* dict = [value mutableCopy];
        for(NSString* ignoredKey in ignored) {
            [dict removeObjectForKey:ignoredKey];
        }

        if(dict.count == [(NSDictionary *)value count]) {
            continue;
        }

        if(dict.count == 0) {
            [userDefaults removeObjectForKey:key];
        } else {
            [userDefaults setObject:[dict copy] forKey:key];
        }
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

    // Per-app kill switch. Distinct from App_Enabled, which means "this app has
    // per-app overrides" — its NO state is "follow global", so it cannot say
    // "off". App_Disabled overrides everything including Global_Enabled, and
    // leaves App_Enabled unset, which is what both ctors gate on: an app the
    // user has excluded is never hooked at all.
    if([[app_settings objectForKey:SHDWAppDisabledID] boolValue]) {
        return [result copy];
    }

    BOOL useAppSettings = [[app_settings objectForKey:@"App_Enabled"] boolValue];

    if(useAppSettings || [userDefaults boolForKey:@"Global_Enabled"]) {
        // Per-app overrides win; a key the app does not set inherits the
        // global value (matches the settings UI).
        [result setObject:@(YES) forKey:@"App_Enabled"];

        for(NSString* key in defaultSettings) {
            id value = useAppSettings ? [app_settings objectForKey:key] : nil;

            if(!value) {
                value = [userDefaults objectForKey:key];
            }

            [result setObject:value forKey:key];
        }
    }

    return [result copy];
}
@end
