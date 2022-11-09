#import "SHDWRootListController.h"

@implementation SHDWRootListController {
	HBPreferences* prefs;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
	}

	return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	return @([prefs boolForKey:[specifier identifier]]);
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	[prefs setObject:value forKey:[specifier identifier]];
}

- (void)respring:(id)sender {
	[HBRespringController respring];
}

- (void)reset:(id)sender {
	[prefs removeAllObjects];
	[self reloadSpecifiers];
	// [self respring:sender];
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [HBPreferences preferencesForIdentifier:@"me.jjolano.shadow"];
	}

	return self;
}
@end
