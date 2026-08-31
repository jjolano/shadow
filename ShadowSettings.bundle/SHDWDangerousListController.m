#import "SHDWDangerousListController.h"
#import "SHDWAppListController.h"
#import "SHDWPrefs.h"
#import "SHDWCapabilities.h"

#import <Shadow/Settings.h>

@implementation SHDWDangerousListController {
	NSUserDefaults* prefs;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Dangerous" target:self];

		// Disable and explain hook rows whose runtime backend is missing.
		SHDWApplyHookGroupGating(_specifiers);
	}

	return _specifiers;
}

- (NSString *)applicationIDInContext {
	// When pushed from the per-app page, inherit its application identifier;
	// otherwise these settings apply globally.
	for(UIViewController* controller in self.navigationController.viewControllers) {
		if([controller isKindOfClass:[SHDWAppListController class]]) {
			return [(SHDWAppListController *)controller applicationID];
		}
	}

	return nil;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	return SHDWReadAppPref(prefs, [self applicationIDInContext], [specifier identifier]);
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	SHDWToggleHaptic();
	SHDWWriteAppPref(prefs, [self applicationIDInContext], [specifier identifier], value);
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
	}

	return self;
}
@end
