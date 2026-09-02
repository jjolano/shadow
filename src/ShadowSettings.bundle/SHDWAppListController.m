#import "SHDWAppListController.h"
#import "SHDWPrefs.h"

#import <Shadow/Settings.h>
#import <AltList/LSApplicationProxy+AltList.h>

@implementation SHDWAppListController {
	NSUserDefaults* prefs;

	// Kept across reloads so the Follow Global toggle can animate this row
	// in/out (native insert/delete) instead of a full table reload; once
	// removed, specifierForID: can no longer find it to put it back.
	PSSpecifier* enabledSpecifier;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"App" target:self];

		enabledSpecifier = [self specifierForID:@"App_Enabled"];

		LSApplicationProxy* proxy = [LSApplicationProxy applicationProxyForIdentifier:[self applicationID]];
		if(proxy.atl_fastDisplayName.length > 0) {
			self.title = proxy.atl_fastDisplayName;
		}

		// Following global = no per-app override; the explicit Enabled row is
		// hidden until the user opts out of the global setting.
		if([self followGlobal]) {
			[self removeSpecifier:enabledSpecifier animated:NO];
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
	}
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
	}
	return self;
}
@end
