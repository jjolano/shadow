#import <Shadow/Settings.h>
#import <RootBridge.h>
#import "../common.h"

@implementation ShadowSettings
@synthesize defaultSettings, userDefaults;

- (instancetype)init {
    if((self = [super init])) {
        defaultSettings = @{
            @"Global_Enabled" : @(NO),
            @"HK_Library" : @"fishhook",
            @"Hook_Filesystem" : @(YES),
            @"Hook_DynamicLibraries" : @(YES),
            @"Hook_URLScheme" : @(YES),
            @"Hook_EnvVars" : @(YES),
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

    if(useAppSettings) {
        // Use app overrides.
        [result setObject:@(YES) forKey:@"App_Enabled"];

        for(NSString* key in defaultSettings) {
            id value = [app_settings objectForKey:key];

            if(!value) {
                id defaultValue = @(NO);

                if([[defaultSettings objectForKey:key] isKindOfClass:[NSString class]]) {
                    defaultValue = [defaultSettings objectForKey:key];
                }

                value = defaultValue;
            }
            
            [result setObject:value forKey:key];
        }
    } else {
        // Use global defaults.
        if([userDefaults boolForKey:@"Global_Enabled"]) {
            [result setObject:@(YES) forKey:@"App_Enabled"];

            for(NSString* key in defaultSettings) {
                [result setObject:[userDefaults objectForKey:key] forKey:key];
            }
        }
    }

    return [result copy];
}
@end
