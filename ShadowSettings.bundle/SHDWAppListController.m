#import "SHDWAppListController.h"

#import <Shadow/Settings.h>
#import <HookKit.h>

@implementation SHDWAppListController {
	NSUserDefaults* prefs;

	NSMutableArray* hk_lib_values;
	NSMutableArray* hk_lib_titles;
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
		id value = prefs_app[[specifier identifier]];
		if(value) return value;
	}

	if([[specifier identifier] isEqualToString:@"HK_Library"]) {
		return [[[ShadowSettings sharedInstance] defaultSettings] objectForKey:@"HK_Library"];
	}

	return nil;
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	NSDictionary* prefs_app = [prefs dictionaryForKey:[self applicationID]];
	NSMutableDictionary* prefs_app_m = prefs_app ? [prefs_app mutableCopy] : [NSMutableDictionary new];

	prefs_app_m[[specifier identifier]] = value;

	[prefs setObject:[prefs_app_m copy] forKey:[self applicationID]];
	[prefs synchronize];
}

- (NSArray *)getValues:(PSSpecifier *)specifier {
	return [hk_lib_values copy];
}

- (NSArray *)getTitles:(PSSpecifier *)specifier {
	return [hk_lib_titles copy];
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];

		hk_lib_values = [NSMutableArray new];
		hk_lib_titles = [NSMutableArray new];

		hookkit_lib_t hooklibs = [HKSubstitutor getAvailableSubstitutorTypes];
		NSArray<NSDictionary *>* hooklibs_info = [HKSubstitutor getSubstitutorTypeInfo:hooklibs];

		[hk_lib_values addObject:@"auto"];
		[hk_lib_titles addObject:[[NSBundle bundleForClass:[self class]] localizedStringForKey:@"AUTOMATIC" value:@"Automatic" table:@"Hooks"]];

        for(NSDictionary* hooklib_info in hooklibs_info) {
			[hk_lib_values addObject:hooklib_info[@"id"]];
			[hk_lib_titles addObject:hooklib_info[@"name"]];
        }
	}

	return self;
}
@end
