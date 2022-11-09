#import <Foundation/Foundation.h>
#import <Preferences/PSSpecifier.h>
#import <Preferences/PSListController.h>
#import <CepheiPrefs/HBRootListController.h>
#import <Cephei/HBPreferences.h>
#import <Cephei/HBRespringController.h>
#import <HBLog.h>

@interface SHDWRootListController : HBRootListController
- (id)readPreferenceValue:(PSSpecifier *)specifier;
- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier;
- (void)respring:(id)sender;
- (void)reset:(id)sender;
@end
