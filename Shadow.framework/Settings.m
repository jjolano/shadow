#import <Shadow/Settings.h>

#import "../common.h"
#import <Shadow/JBPath.h>
#import <Shadow/HookConfiguration.h>

@implementation ShadowSettings
@synthesize defaultSettings, userDefaults;

- (instancetype)init {
    if((self = [super init])) {
        // Canonical shipped defaults (Shadow/HookConfiguration.h) — the
        // metadata is the single source of truth. Hook_IOKit is explicit NO
        // (previously absent-by-omission).
        defaultSettings = SHDWDefaultHookSettings();

        userDefaults = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
        [userDefaults registerDefaults:defaultSettings];
    }

    return self;
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

            // Absent everywhere (a key added by an upgrade, or a Sandy-
            // filtered read): keep the shipped default already in result.
            // setObject:nil here would throw and abort the whole ctor.
            if(value) {
                [result setObject:value forKey:key];
            }
        }
    }

    return [result copy];
}
@end
