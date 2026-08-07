#import "ATLApplicationListControllerBase.h"

@interface ATLApplicationListMultiSelectionController : ATLApplicationListControllerBase
{
	NSMutableSet* _selectedApplications;
	BOOL _defaultApplicationSwitchValue;
}

- (void)setApplicationEnabled:(NSNumber*)enabledNum specifier:(PSSpecifier*)specifier;
- (id)readApplicationEnabled:(PSSpecifier*)specifier;

@end