#import "SHDWHooksListController.h"

@implementation SHDWHooksListController
- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Hooks" target:self];
	}

	return _specifiers;
}
@end
