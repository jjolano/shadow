#import "SHDWHooksListController.h"

#import <Shadow/Settings.h>
#import <HookKit.h>

@implementation SHDWHooksListController {
	NSUserDefaults* prefs;

	NSMutableArray* hk_lib_values;
	NSMutableArray* hk_lib_titles;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Hooks" target:self];
		[self setTitle:@"Bypass Settings"];
	}

	return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	return [prefs objectForKey:[specifier identifier]];
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	[prefs setObject:value forKey:[specifier identifier]];
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
