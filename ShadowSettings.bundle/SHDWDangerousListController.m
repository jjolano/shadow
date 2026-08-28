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
		BOOL detectorPane = [[self.specifier propertyForKey:@"detectorPane"] boolValue];
		NSUInteger detectorStart = NSNotFound;
		for(NSUInteger i = 0; i < _specifiers.count; i++) {
			if([[[_specifiers objectAtIndex:i] identifier] isEqualToString:@"DetectorPatchesGroup"]) {
				detectorStart = i;
				break;
			}
		}
		if(detectorStart != NSNotFound) {
			// ponytail: detector rows stay last; add an end marker if another
			// dangerous section is ever appended below them.
			_specifiers = [(detectorPane
				? [_specifiers subarrayWithRange:NSMakeRange(detectorStart, _specifiers.count - detectorStart)]
				: [_specifiers subarrayWithRange:NSMakeRange(0, detectorStart)]) mutableCopy];
		}
		if(detectorPane) {
			self.title = [[NSBundle bundleForClass:[self class]]
				localizedStringForKey:@"DETECTOR_PATCHES" value:nil table:@"Dangerous"];
		}

		// Disable and explain hook rows whose runtime backend is missing.
		SHDWApplyHookGroupGating(_specifiers);
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
	return SHDWReadAppPref(prefs, [self applicationIDInContext], [specifier identifier]);
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	SHDWToggleHaptic();
	SHDWWriteAppPref(prefs, [self applicationIDInContext], [specifier identifier], value);
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
	}

	return self;
}
@end
