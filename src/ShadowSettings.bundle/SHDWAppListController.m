#import "SHDWAppListController.h"
#import "SHDWPrefs.h"

#import <Shadow/Settings.h>
#import <AltList/LSApplicationProxy+AltList.h>

@implementation SHDWAppListController {
	NSUserDefaults* prefs;

	// Kept across reloads so the single Follow Global toggle can animate both
	// per-app rows in/out (native insert/delete) instead of a full table
	// reload; once removed, specifierForID: can no longer find them to put
	// them back.
	PSSpecifier* enabledSpecifier;
	PSSpecifier* aggressiveSpecifier;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"App" target:self];

		enabledSpecifier = [self specifierForID:@"App_Enabled"];
		aggressiveSpecifier = [self specifierForID:@"Detector_Aggressive"];

		LSApplicationProxy* proxy = [LSApplicationProxy applicationProxyForIdentifier:[self applicationID]];
		if(proxy.atl_fastDisplayName.length > 0) {
			self.title = proxy.atl_fastDisplayName;
		}

		// One Follow Global toggle governs the whole app: following global =
		// no per-app overrides, so both the activation and aggressive rows are
		// hidden until the user opts out.
		if([self followGlobal]) {
			[self removeSpecifier:enabledSpecifier animated:NO];
			[self removeSpecifier:aggressiveSpecifier animated:NO];
		}

		[self updateSettingsGroupFooter];
	}
	return _specifiers;
}

- (BOOL)followGlobal {
	return SHDWAppFollowsGlobal(prefs, [self applicationID]);
}

// Group footer explains the current state; the group is found by id (its
// display name is localized) and the footer is written already-localized.
- (void)updateSettingsGroupFooter {
	NSBundle* bundle = [NSBundle bundleForClass:[self class]];
	PSSpecifier* settingsGroup = [self specifierForID:@"AppSettingsGroup"];
	if(!settingsGroup) {
		return;
	}

	NSString* footer = [self followGlobal]
		? [bundle localizedStringForKey:@"APP_USES_GLOBAL" value:@"Following the global settings. Turn off to customize this app." table:@"App"]
		: [bundle localizedStringForKey:@"APP_SETTINGS_DESC" value:@"Enable Shadow for this application. Shadow uses its built-in bypass profile." table:@"App"];
	[settingsGroup setProperty:footer forKey:@"footerText"];
	[self reloadSpecifier:settingsGroup];
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	NSString* key = [specifier identifier];

	if([key isEqualToString:@"App_FollowGlobal"]) {
		return @([self followGlobal]);
	}

	if([key isEqualToString:@"App_Enabled"]) {
		return @(SHDWAppEnabled(prefs, [self applicationID]));
	}

	if([key isEqualToString:@"Detector_Aggressive"]) {
		return @(SHDWAppAggressive(prefs, [self applicationID]));
	}

	return nil;
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	SHDWToggleHaptic();
	NSString* key = [specifier identifier];

	if([key isEqualToString:@"App_FollowGlobal"]) {
		// A single Follow Global toggle governs the whole app. Following global
		// clears both per-app overrides and hides both explicit rows; opting
		// out seeds each from its current effective state and reveals both.
		// Rows animate in/out like Settings' own conditional rows instead of a
		// full table reload.
		if([value boolValue]) {
			SHDWClearAppEnabled(prefs, [self applicationID]);
			SHDWClearAppAggressive(prefs, [self applicationID]);
			[self removeSpecifier:aggressiveSpecifier animated:YES];
			[self removeSpecifier:enabledSpecifier animated:YES];
		} else {
			SHDWWriteAppEnabled(prefs, [self applicationID], SHDWAppEnabled(prefs, [self applicationID]));
			SHDWWriteAppAggressive(prefs, [self applicationID], SHDWAppAggressive(prefs, [self applicationID]));
			// App_Enabled sits under the activation group (after the toggle);
			// Detector_Aggressive sits under its own group header.
			[self insertSpecifier:enabledSpecifier afterSpecifier:[self specifierForID:@"App_FollowGlobal"] animated:YES];
			[self insertSpecifier:aggressiveSpecifier afterSpecifier:[self specifierForID:@"AppAggressiveGroup"] animated:YES];
			[self reloadSpecifier:enabledSpecifier];
			[self reloadSpecifier:aggressiveSpecifier];
		}
		[self updateSettingsGroupFooter];
		return;
	}

	if([key isEqualToString:@"App_Enabled"]) {
		SHDWWriteAppEnabled(prefs, [self applicationID], [value boolValue]);
		return;
	}

	if([key isEqualToString:@"Detector_Aggressive"]) {
		SHDWWriteAppAggressive(prefs, [self applicationID], [value boolValue]);
	}
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
	}
	return self;
}
@end
