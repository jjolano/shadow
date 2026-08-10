#import <Foundation/Foundation.h>
#import <Preferences/PSSpecifier.h>
#import <Preferences/PSListController.h>

#import <AltList/ATLApplicationListSubcontroller.h>

@interface SHDWAppListController : ATLApplicationListSubcontroller
- (id)readPreferenceValue:(PSSpecifier *)specifier;
- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier;
- (NSArray *)getValues:(PSSpecifier *)specifier;
- (NSArray *)getTitles:(PSSpecifier *)specifier;
@end
