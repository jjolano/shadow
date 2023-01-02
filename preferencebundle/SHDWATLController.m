#import "SHDWATLController.h"
#import "../api/ShadowService+Settings.h"

@implementation SHDWATLController {
	NSUserDefaults* prefs;
}

- (NSString *)previewStringForApplicationWithIdentifier:(NSString *)applicationID {
    // read enabled status for applicationID
    NSDictionary* app_settings = [prefs objectForKey:applicationID];

    if(app_settings) {
        // show "Enabled" label if shadow is enabled in app
        if(app_settings[@"App_Enabled"] && [app_settings[@"App_Enabled"] boolValue]) {
            return @"Enabled";
        }
    }

    return @"";
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [ShadowService getUserDefaults];
	}

	return self;
}
@end
