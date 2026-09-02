#import "SHDWATLController.h"
#import "SHDWPrefs.h"
#import <Shadow/Settings.h>

@implementation SHDWATLController {
	NSUserDefaults* prefs;
}

- (NSString *)previewStringForApplicationWithIdentifier:(NSString *)applicationID {
	return SHDWAppEnabled(prefs, applicationID)
		? [[NSBundle bundleForClass:[self class]] localizedStringForKey:@"ENABLED" value:@"Enabled" table:@"App"]
		: @"";
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
	}

	return self;
}
@end
