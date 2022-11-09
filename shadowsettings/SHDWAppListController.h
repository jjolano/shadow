#import <Foundation/Foundation.h>
#import <Preferences/PSSpecifier.h>
#import <Preferences/PSListController.h>
#import <CepheiPrefs/HBListController.h>
#import <Cephei/HBPreferences.h>
#import <AltList/ATLApplicationListSubcontroller.h>
#import <HBLog.h>

@interface SHDWAppListController : ATLApplicationListSubcontroller
- (id)readPreferenceValue:(PSSpecifier *)specifier;
- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier;
@end
