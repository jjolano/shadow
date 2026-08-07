#import "SHDWATLController.h"
#import <Shadow/Settings.h>

@implementation SHDWATLController {
	NSUserDefaults* prefs;
}

- (NSString *)previewStringForApplicationWithIdentifier:(NSString *)applicationID {
    // read enabled status for applicationID
    NSDictionary* app_settings = [prefs objectForKey:applicationID];

    if(app_settings) {
        // show "Enabled" label if shadow is enabled in app
        if(app_settings[@"App_Enabled"] && [app_settings[@"App_Enabled"] boolValue]) {
            return [[NSBundle bundleForClass:[self class]] localizedStringForKey:@"ENABLED" value:@"Enabled" table:@"App"];
        }
    }

    // the app is covered by the global setting
    if([prefs boolForKey:@"Global_Enabled"]) {
        return [[NSBundle bundleForClass:[self class]] localizedStringForKey:@"ENABLED_GLOBAL" value:@"Enabled (Global)" table:@"App"];
    }

    return @"";
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
	}

	return self;
}
@end
