#import "SHDWHooksListController.h"
#import "../api/ShadowService+Settings.h"

@implementation SHDWHooksListController {
	NSUserDefaults* prefs;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Hooks" target:self];
		[self setTitle:@"Bypass Settings"];
	}

	return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	return @([prefs boolForKey:[specifier identifier]]);
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	[prefs setObject:value forKey:[specifier identifier]];
	[prefs synchronize];
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [ShadowService getUserDefaults];
	}

	return self;
}
@end
