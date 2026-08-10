#import <Preferences/PSListController.h>

@interface SHDWIndividualListController : PSListController
- (id)readPreferenceValue:(PSSpecifier *)specifier;
- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier;
@end
