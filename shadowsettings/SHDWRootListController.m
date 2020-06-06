#include "SHDWRootListController.h"

#import <Cephei/HBPreferences.h>
#import <Cephei/HBRespringController.h>

@implementation SHDWRootListController

- (NSArray *)specifiers {
	if (!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
	}

	return _specifiers;
}

- (void)respring {
	[HBRespringController respring];
}

- (void)resetSettings {
	HBPreferences* shadowPrefs = [HBPreferences preferencesForIdentifier:@"me.jjolano.shadow"];

	if(shadowPrefs) {
		[shadowPrefs removeAllObjects];
	}

	[self respring];
}

@end
