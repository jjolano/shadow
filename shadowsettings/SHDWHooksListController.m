#import "SHDWHooksListController.h"

@implementation SHDWHooksListController {
	HBPreferences* prefs;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Hooks" target:self];
		[self setTitle:@"Hooks"];
	}

	return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	return @([prefs boolForKey:[specifier identifier]]);
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	[prefs setObject:value forKey:[specifier identifier]];
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [HBPreferences preferencesForIdentifier:@"me.jjolano.shadow"];
	}

	return self;
}
@end
