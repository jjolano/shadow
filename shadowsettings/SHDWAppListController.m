#import "SHDWAppListController.h"

@implementation SHDWAppListController
- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"App" target:self];
		[_specifiers addObjectsFromArray:[self loadSpecifiersFromPlistName:@"Hooks" target:self]];
	}

	return _specifiers;
}
@end
