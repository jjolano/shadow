#import "SHDWAppListController.h"

@implementation SHDWAppListController {
	HBPreferences* prefs;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"App" target:self];
		[_specifiers addObjectsFromArray:[self loadSpecifiersFromPlistName:@"Hooks" target:self]];
	}

	return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	if(prefs[[self applicationID]]) {
		return @([prefs[[self applicationID]][[specifier identifier]] boolValue]);
	}

	return @(NO);
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	if(!prefs[[self applicationID]]) {
		prefs[[self applicationID]] = [NSMutableDictionary new];
	}

	NSMutableDictionary* prefs_app = [NSMutableDictionary dictionaryWithDictionary:prefs[[self applicationID]]];
	prefs_app[[specifier identifier]] = value;

	[prefs setObject:[prefs_app copy] forKey:[self applicationID]];
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [HBPreferences preferencesForIdentifier:@"me.jjolano.shadow"];
	}

	return self;
}
@end
