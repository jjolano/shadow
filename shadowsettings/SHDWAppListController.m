#import "SHDWAppListController.h"

@implementation SHDWAppListController
- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"App" target:self];
	}

	return _specifiers;
}
@end
