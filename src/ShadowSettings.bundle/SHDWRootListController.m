#import "SHDWRootListController.h"
#import "SHDWPrefs.h"

#import <Shadow/Core+Utilities.h>
#import <Shadow/Settings.h>
#import <Shadow/HookConfiguration.h>

@implementation SHDWRootListController {
	NSUserDefaults* prefs;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
		for(NSString* identifier in @[@"ApplicationsSummary", @"RootAbout"]) {
			UIImage* icon = SHDWSettingsSymbol([identifier isEqualToString:@"RootAbout"] ? @"info.circle" : @"square.grid.2x2");
			if(icon) [[self specifierForID:identifier] setProperty:icon forKey:@"iconImage"];
		}
	}

	return _specifiers;
}

- (NSString *)localized:(NSString *)key fallback:(NSString *)fallback {
	return [[NSBundle bundleForClass:[self class]] localizedStringForKey:key value:fallback table:@"Root"];
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	NSString* key = [specifier identifier];

	if([key isEqualToString:@"ApplicationsSummary"]) {
		// Count apps not following the global settings: an app "follows
		// global" until it writes an explicit activation override (App_Enabled)
		// or a per-app aggressive override (Detector_Aggressive). Legacy
		// App_Disabled counts too, since it also overrides the global toggle.
		// The subtext is a bare number; with no overrides there is nothing to
		// display, so omit the label entirely.
		NSInteger customized = 0;
		for(id value in [prefs dictionaryRepresentation].allValues) {
			if(SHDWAppIsCustomized(value)) {
				customized++;
			}
		}

		if(customized == 0) {
			return nil;
		}

		return [NSString stringWithFormat:@"%ld", (long)customized];
	}

	return [prefs objectForKey:[specifier identifier]];
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	SHDWToggleHaptic();
	[prefs setObject:value forKey:[specifier identifier]];
	[prefs synchronize];
}

- (void)viewWillAppear:(BOOL)animated {
	[super viewWillAppear:animated];

	// Re-read on return: the summary derives from switches changed on pushed
	// app pages, and the global switches can be wiped by Reset Settings in the
	// About pane. Without this, popping back shows stale switch/summary state
	// even though the stored values changed.
	for(NSString* specID in @[ @"Global_Enabled", @"Detector_Aggressive", @"ApplicationsSummary" ]) {
		PSSpecifier* specifier = [self specifierForID:specID];
		if(specifier) {
			[self reloadSpecifier:specifier];
		}
	}
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
	}

	return self;
}
@end
