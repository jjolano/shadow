#import <Foundation/Foundation.h>
#import "SHDWRootListController.h"

@implementation SHDWRootListController

- (NSArray *)specifiers {
	if (!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
	}

	return _specifiers;
}

@end
