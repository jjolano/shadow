#import "SHDWRootListController.h"

@implementation SHDWRootListController
- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
	}

	return _specifiers;
}

- (void)respring:(id)sender {
	[HBRespringController respring];
}

- (void)reset:(id)sender {
	HBPreferences* prefs = [HBPreferences preferencesForIdentifier:@"me.jjolano.shadow"];
	[prefs removeAllObjects];
	[self respring:sender];
}
@end
