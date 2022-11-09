#import "SHDWHooksListController.h"

@implementation SHDWHooksListController
- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Hooks" target:self];
		[self setTitle:@"Hooks"];
	}

	return _specifiers;
}
@end
