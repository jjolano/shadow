#import <Shadow/Settings.h>
#import <RootBridge.h>
#import "../common.h"

@implementation ShadowSettings
@synthesize defaultSettings, userDefaults;

- (instancetype)init {
    if((self = [super init])) {
        defaultSettings = @{
            @"Global_Enabled" : @(NO),
            @"HK_Library" : @"auto",
            @"Hook_Filesystem" : @(YES),
            @"Hook_DynamicLibraries" : @(YES),
            @"Hook_URLScheme" : @(YES),
            @"Hook_EnvVars" : @(YES),
            @"Hook_Foundation" : @(NO),
            @"Hook_DeviceCheck" : @(YES),
            @"Hook_MachBootstrap" : @(NO),
            // C0-4: safe groups on by default — off-by-default = that vector
            // is 100% exposed on a default install (detectors enumerate the
            // dyld/objc surface before any pref can be flipped). The blanket
            // denial groups below (Sandbox, Memory, Syscall, AntiDebugging,
            // FakeMac) stay opt-in: they break legitimate apps.
            @"Hook_SymLookup" : @(YES),
            @"Hook_LowLevelC" : @(YES),
            @"Hook_AntiDebugging" : @(NO),
            @"Hook_DynamicLibrariesExtra" : @(NO),
            @"Hook_ObjCRuntime" : @(YES),
            @"Hook_FakeMac" : @(NO),
            @"Hook_Syscall" : @(NO),
            @"Hook_Sandbox" : @(NO),
            @"Hook_Memory" : @(NO),
            @"Hook_TweakClasses" : @(YES),
            @"Hook_HideApps" : @(YES),
            @"MemoryLevelHiding" : @(NO),
            @"VnodeHiding" : @(NO)
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
				// Inherit the global value for options the app does not override.
				value = [userDefaults objectForKey:key];
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
