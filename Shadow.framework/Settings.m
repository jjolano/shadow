#import <Shadow/Settings.h>

#import "../common.h"
#import <Shadow/JBPath.h>

@implementation ShadowSettings
@synthesize defaultSettings, userDefaults;

- (instancetype)init {
    if((self = [super init])) {
        defaultSettings = @{
            @"Global_Enabled" : @(NO),
            @"HK_Library" : @"auto",
            @"Hook_Filesystem" : @(YES),
            @"Hook_URLScheme" : @(YES),
            @"Hook_EnvVars" : @(YES),
            @"Hook_Foundation" : @(NO),
            @"Hook_DeviceCheck" : @(YES),
            @"Hook_MachBootstrap" : @(NO),
            // C0-4: identity groups (dyld/objc/classes/symlookup) are forced
            // on unconditionally — off-by-default = that vector is 100%
            // exposed on a default install (detectors enumerate the dyld/objc
            // surface before any pref can be flipped). The remaining groups
            // stay opt-in (defaults below): the blanket denial groups
            // (Sandbox, Memory, Syscall, AntiDebugging, FakeMac) break
            // legitimate apps.
            @"Hook_LowLevelC" : @(YES),
            @"Hook_AntiDebugging" : @(NO),
            @"Hook_DynamicLibrariesExtra" : @(NO),
            @"Hook_FakeMac" : @(NO),
            @"Hook_Syscall" : @(NO),
            @"Hook_Sandbox" : @(NO),
            @"Hook_Memory" : @(NO),
            @"Hook_HideApps" : @(YES),
            @"VnodeHiding" : @(NO),
            // AR2 emergency kill-switch: the dyld_all_image_infos memory-hiding
            // patch is unconditional by default (untrusted callers read the raw
            // struct), but a misbehaving patch on a new iOS must be disableable
            // without a reinstall. Default YES (patch on); flipping to NO
            // restores dyld's original struct and stops the patch — detection
            // exposure returns, crashes stop.
            @"MemoryLevelHiding" : @(YES)
        };

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
