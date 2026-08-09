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
        // (previously absent-by-omission); the stale Hook_FakeMac key is
        // dropped (accepted-but-ignored for legacy preference files).
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
