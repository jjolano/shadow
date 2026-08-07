#import "SHDWDangerousListController.h"
#import "SHDWAppListController.h"

#import <Shadow/Settings.h>

@implementation SHDWDangerousListController {
	NSUserDefaults* prefs;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Dangerous" target:self];
	}

	return _specifiers;
}

- (NSString *)applicationIDInContext {
	// When pushed from the per-app page, inherit its application identifier;
	// otherwise these settings apply globally.
	for(UIViewController* controller in self.navigationController.viewControllers) {
		if([controller isKindOfClass:[SHDWAppListController class]]) {
			return [(SHDWAppListController *)controller applicationID];
		}
	}

	return nil;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	NSString* applicationID = [self applicationIDInContext];

	if(applicationID) {
		NSDictionary* prefs_app = [prefs dictionaryForKey:applicationID];
		NSString* key = [specifier identifier];

		if(prefs_app && [prefs_app objectForKey:key]) {
			return prefs_app[key];
		}

		// Options not overridden for this app inherit the global value.
		return [prefs objectForKey:key];
	}

	return [prefs objectForKey:[specifier identifier]];
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	NSString* applicationID = [self applicationIDInContext];

	if(applicationID) {
		NSDictionary* prefs_app = [prefs dictionaryForKey:applicationID];
		NSMutableDictionary* prefs_app_m = prefs_app ? [prefs_app mutableCopy] : [NSMutableDictionary new];

		prefs_app_m[[specifier identifier]] = value;

		[prefs setObject:[prefs_app_m copy] forKey:applicationID];
	} else {
		[prefs setObject:value forKey:[specifier identifier]];
	}

	[prefs synchronize];
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
	}

	return self;
}
@end
