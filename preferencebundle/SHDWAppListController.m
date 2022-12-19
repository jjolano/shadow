#import "SHDWAppListController.h"
#import "../api/ShadowSettings.h"

@implementation SHDWAppListController {
	NSUserDefaults* prefs;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"App" target:self];
		[_specifiers addObjectsFromArray:[self loadSpecifiersFromPlistName:@"Hooks" target:self]];
	}

	return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	NSDictionary* prefs_app = [prefs dictionaryForKey:[self applicationID]];

	if(prefs_app) {
		NSNumber* value = prefs_app[[specifier identifier]];
		return @(value && [value boolValue]);
	}

	return @(NO);
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	NSMutableDictionary* prefs_app = [prefs dictionaryForKey:[self applicationID]] ? [[prefs dictionaryForKey:[self applicationID]] mutableCopy] : nil;

	if(!prefs_app) {
		prefs_app = [NSMutableDictionary new];
	}

	prefs_app[[specifier identifier]] = value;

	[prefs setObject:[prefs_app copy] forKey:[self applicationID]];
	[prefs synchronize];
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [ShadowSettings getUserDefaults];
	}

	return self;
}
@end
