#import "SHDWAppListController.h"
#import "SHDWPrefs.h"

#import <Shadow/Settings.h>
#import <AltList/LSApplicationProxy+AltList.h>

@implementation SHDWAppListController {
	NSUserDefaults* prefs;

	// Kept across reloads so the Follow Global toggles can animate their rows
	// in/out (native insert/delete) instead of a full table reload; once
	// removed, specifierForID: can no longer find them to put them back.
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

		// Following global = no per-app override; the explicit row is hidden
		// until the user opts out of the corresponding global setting.
		if([self followGlobal]) {
			[self removeSpecifier:enabledSpecifier animated:NO];
		}
		if([self aggressiveFollowGlobal]) {
			[self removeSpecifier:aggressiveSpecifier animated:NO];
		}

		[self updateSettingsGroupFooter];
	}
	return _specifiers;
}

- (BOOL)aggressiveFollowGlobal {
	return SHDWAppAggressiveFollowsGlobal(prefs, [self applicationID]);
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

	if([key isEqualToString:@"App_AggressiveFollowGlobal"]) {
		return @([self aggressiveFollowGlobal]);
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
		// Following global = clear the per-app override and hide the explicit
		// Enabled row; opting out writes an explicit value (seeded from the
		// current effective state) and reveals it. Rows animate in/out like
		// Settings' own conditional rows instead of a full table reload.
		if([value boolValue]) {
			SHDWClearAppEnabled(prefs, [self applicationID]);
			[self removeSpecifier:enabledSpecifier animated:YES];
		} else {
			SHDWWriteAppEnabled(prefs, [self applicationID], SHDWAppEnabled(prefs, [self applicationID]));
			[self insertSpecifier:enabledSpecifier afterSpecifier:[self specifierForID:@"App_FollowGlobal"] animated:YES];
			[self reloadSpecifier:enabledSpecifier];
		}
		[self updateSettingsGroupFooter];
		return;
	}

	if([key isEqualToString:@"App_Enabled"]) {
		SHDWWriteAppEnabled(prefs, [self applicationID], [value boolValue]);
		return;
	}

	if([key isEqualToString:@"App_AggressiveFollowGlobal"]) {
		// Same conditional-row pattern as activation: following global clears
		// the per-app override and hides the explicit switch; opting out seeds
		// an explicit value from the current effective state and reveals it.
		if([value boolValue]) {
			SHDWClearAppAggressive(prefs, [self applicationID]);
			[self removeSpecifier:aggressiveSpecifier animated:YES];
		} else {
			SHDWWriteAppAggressive(prefs, [self applicationID], SHDWAppAggressive(prefs, [self applicationID]));
			[self insertSpecifier:aggressiveSpecifier afterSpecifier:[self specifierForID:@"App_AggressiveFollowGlobal"] animated:YES];
			[self reloadSpecifier:aggressiveSpecifier];
		}
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
