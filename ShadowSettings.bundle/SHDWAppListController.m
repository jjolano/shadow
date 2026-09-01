#import "SHDWAppListController.h"
#import "SHDWPrefs.h"

#import <Shadow/Settings.h>
#import <AltList/LSApplicationProxy+AltList.h>

@implementation SHDWAppListController {
	NSUserDefaults* prefs;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"App" target:self];
		LSApplicationProxy* proxy = [LSApplicationProxy applicationProxyForIdentifier:[self applicationID]];
		if(proxy.atl_fastDisplayName.length > 0) {
			self.title = proxy.atl_fastDisplayName;
		}
	}
	return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	if([[specifier identifier] isEqualToString:@"App_Enabled"]) {
		return @(SHDWAppEnabled(prefs, [self applicationID]));
	}
	return nil;
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	if([[specifier identifier] isEqualToString:@"App_Enabled"]) {
		SHDWToggleHaptic();
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
