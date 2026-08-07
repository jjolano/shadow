#import <Preferences/PSListController.h>

@interface SHDWDangerousListController : PSListController
- (id)readPreferenceValue:(PSSpecifier *)specifier;
- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier;
@end
