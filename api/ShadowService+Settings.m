#import "ShadowService+Settings.h"

@implementation ShadowService (Settings)
+ (NSDictionary *)getDefaultPreferences {
    return @{
        @"Global_Enabled" : @(NO),
        @"HK_Library" : @"auto",
        @"Tweak_CompatEx" : @(NO),
        @"Rootless" : @(NO),
        @"Hook_Filesystem" : @(YES),
        @"Hook_DynamicLibraries" : @(YES),
        @"Hook_URLScheme" : @(YES),
        @"Hook_EnvVars" : @(YES),
        @"Hook_FilesystemExtra" : @(NO),
        @"Hook_Foundation" : @(NO),
        @"Hook_DeviceCheck" : @(YES),
        @"Hook_MachBootstrap" : @(NO),
        @"Hook_SymLookup" : @(NO),
        @"Hook_LowLevelC" : @(NO),
        @"Hook_AntiDebugging" : @(NO),
        @"Hook_DynamicLibrariesExtra" : @(NO),
        @"Hook_ObjCRuntime" : @(NO),
        @"Hook_FakeMac" : @(NO),
        @"Hook_Syscall" : @(NO),
        @"Hook_Sandbox" : @(NO),
        @"Hook_Memory" : @(NO),
        @"Hook_TweakClasses" : @(NO),
        @"Hook_HideApps" : @(NO)
    };
}

+ (NSUserDefaults *)getUserDefaults {
    static dispatch_once_t once;
    static NSUserDefaults* userDefaults;

    dispatch_once(&once, ^{
        userDefaults = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
        [userDefaults registerDefaults:[self getDefaultPreferences]];
    });

    return userDefaults;
}

+ (NSDictionary *)getPreferences:(NSString *)bundleIdentifier {
    NSDictionary* default_prefs = [self getDefaultPreferences];
    NSMutableDictionary* result = [default_prefs mutableCopy];
    NSUserDefaults* shdw_prefs = [self getUserDefaults];
    NSDictionary* app_settings = [shdw_prefs objectForKey:bundleIdentifier];

    if(app_settings && app_settings[@"App_Enabled"] && [app_settings[@"App_Enabled"] boolValue]) {
        // Use app overrides.
        [result setObject:@(YES) forKey:@"App_Enabled"];

        for(NSString* key in default_prefs) {
            id value = [app_settings objectForKey:key];
            id defaultValue = @(NO);

            if([default_prefs[key] isKindOfClass:[NSString class]]) {
                defaultValue = default_prefs[key];
            }

            if(!value) {
                value = defaultValue;
            }
            
            [result setObject:value forKey:key];
        }
    } else {
        // Use global defaults.
        if([shdw_prefs boolForKey:@"Global_Enabled"]) {
            [result setObject:@(YES) forKey:@"App_Enabled"];

            for(NSString* key in default_prefs) {
                [result setObject:[shdw_prefs objectForKey:key] forKey:key];
            }
        }
    }

    return [result copy];
}

+ (NSDictionary *)getPreferences:(NSString *)bundleIdentifier usingService:(ShadowService *)service {
    if(!service) {
        return nil;
    }

    return [service sendIPC:@"getPreferences" withArgs:@{@"bundleIdentifier" : bundleIdentifier}];
}
@end
