#import "SHDWAppListController.h"
#import "SHDWHookLibs.h"
#import "SHDWPrefs.h"

#import <Preferences/PSListController.h>
#import <Shadow/Settings.h>

@interface SHDWTroubleshootingListController : PSListController
@end

@implementation SHDWTroubleshootingListController {
	NSUserDefaults* prefs;
	NSArray* hookLibraryValues;
	NSArray* hookLibraryTitles;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Troubleshooting" target:self];
	}

	return _specifiers;
}

- (NSString *)applicationIDInContext {
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

- (NSArray *)getValues:(PSSpecifier *)specifier {
	return hookLibraryValues;
}

- (NSArray *)getTitles:(PSSpecifier *)specifier {
	return hookLibraryTitles;
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];

		NSMutableArray* values = [NSMutableArray arrayWithObject:@"auto"];
		NSBundle* bundle = [NSBundle bundleForClass:[self class]];
		NSMutableArray* titles = [NSMutableArray arrayWithObject:
			[bundle localizedStringForKey:@"AUTOMATIC" value:@"Automatic (Recommended)" table:@"Troubleshooting"]];

		for(NSDictionary* info in SHDWAvailableHookLibs()) {
			[values addObject:info[@"id"]];
			[titles addObject:info[@"name"]];
		}

		hookLibraryValues = [values copy];
		hookLibraryTitles = [titles copy];
	}

	return self;
}
@end
