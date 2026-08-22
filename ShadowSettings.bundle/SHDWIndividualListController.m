#import "SHDWIndividualListController.h"
#import "SHDWAppListController.h"
#import "SHDWPrefs.h"
#import "SHDWCapabilities.h"

#import <Shadow/Settings.h>

@implementation SHDWIndividualListController {
	NSUserDefaults* prefs;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Individual" target:self];

		// Same capability gating as the other hook pages: toggles can't run
		// a group the device's backends don't support.
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

- (void)viewWillAppear:(BOOL)animated {
	[super viewWillAppear:animated];

	// The preset classification on the parent page derives from these
	// toggles; refresh the preset row on return.
	PSSpecifier* presetSpecifier = [self specifierForID:@"BypassPreset"];
	if(presetSpecifier) {
		[self reloadSpecifier:presetSpecifier];
	}
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
	}

	return self;
}
@end
