#import "SHDWDangerousListController.h"
#import "SHDWAppListController.h"
#import "SHDWPrefs.h"
#import "SHDWCapabilities.h"

#import <Shadow/Settings.h>

@implementation SHDWDangerousListController {
	NSUserDefaults* prefs;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Dangerous" target:self];

		// VnodeHiding needs the shadowd daemon with krw ready;
		// Hook_DynamicLibrariesExtra needs ElleKit. Disable + explain when
		// the runtime backend is missing. Gate instantly with cached state,
		// then re-gate when the async daemon refresh lands (never block the
		// initial render on Mach IPC).
		SHDWApplyHookGroupGating(_specifiers);
		[self refreshDaemonStateAndRegate];
	}

	return _specifiers;
}

- (void)refreshDaemonStateAndRegate {
	__weak typeof(self) weakSelf = self;

	SHDWRefreshDaemonStateAsync(^(SHDWDaemonState state) {
		typeof(self) self = weakSelf;
		if(!self) {
			return;
		}

		SHDWApplyHookGroupGating(self->_specifiers);
		[self reloadSpecifiers];
	});
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
	return SHDWReadAppPref(prefs, [self applicationIDInContext], [specifier identifier]);
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	SHDWWriteAppPref(prefs, [self applicationIDInContext], [specifier identifier], value);
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
	}

	return self;
}
@end
