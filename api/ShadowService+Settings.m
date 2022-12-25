#import "ShadowService+Settings.h"

@implementation ShadowService (Settings)
+ (NSDictionary *)getDefaultPreferences {
    return @{
        @"Global_Enabled" : @(NO),
        @"Tweak_CompatEx" : @(NO),
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
        @"Hook_TweakClasses" : @(NO)
    };
}

+ (NSUserDefaults *)getUserDefaults {
    NSUserDefaults* result = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
    [result registerDefaults:[self getDefaultPreferences]];
    return result;
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
            [result setObject:(app_settings[key] ? @([app_settings[key] boolValue]) : @(NO)) forKey:key];
        }
    } else {
        // Use global defaults.
        if([shdw_prefs boolForKey:@"Global_Enabled"]) {
            [result setObject:@(YES) forKey:@"App_Enabled"];
        }

        for(NSString* key in default_prefs) {
            [result setObject:@([shdw_prefs boolForKey:key]) forKey:key];
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
