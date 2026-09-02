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
	}

	return _specifiers;
}

- (NSString *)localized:(NSString *)key fallback:(NSString *)fallback {
	return [[NSBundle bundleForClass:[self class]] localizedStringForKey:key value:fallback table:@"Root"];
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	NSString* key = [specifier identifier];

	if([key isEqualToString:@"ApplicationsSummary"]) {
		NSInteger excluded = 0;
		for(id value in [prefs dictionaryRepresentation].allValues) {
			if([value isKindOfClass:[NSDictionary class]] &&
			   ([[value objectForKey:SHDWAppDisabledID] boolValue] ||
			    ([value objectForKey:SHDWAppEnabledID] && ![[value objectForKey:SHDWAppEnabledID] boolValue]))) {
				excluded++;
			}
		}

		// Global_Enabled makes every eligible app active, so the summary is
		// trivial — unless some apps are explicitly excluded, which "all apps
		// enabled" would misreport.
		if([prefs boolForKey:@"Global_Enabled"]) {
			if(excluded == 0) {
				return [self localized:@"APPS_ALL_ENABLED" fallback:@"All apps enabled"];
			}

			return [NSString stringWithFormat:[self localized:@"APPS_EXCLUDED_FMT" fallback:@"All apps enabled · %ld excluded"], (long)excluded];
		}

		NSInteger count = 0;
		for(id value in [prefs dictionaryRepresentation].allValues) {
			if([value isKindOfClass:[NSDictionary class]] && [[value objectForKey:SHDWAppEnabledID] boolValue]
				&& ![[value objectForKey:SHDWAppDisabledID] boolValue]) {
				count++;
			}
		}

		return [NSString stringWithFormat:[self localized:@"APPS_ENABLED_FMT" fallback:@"%ld enabled"], (long)count];
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

	// The summary derives from switches changed on pushed app pages.
	for(NSString* specID in @[ @"ApplicationsSummary" ]) {
		PSSpecifier* summary = [self specifierForID:specID];
		if(summary) {
			[self reloadSpecifier:summary];
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
