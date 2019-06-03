#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Preferences/PSListController.h>
#import <CepheiPrefs/HBRootListController.h>
#import <CepheiPrefs/HBAppearanceSettings.h>
#import <Cephei/HBPreferences.h>
#import <Cephei/HBRespringController.h>
#import "../Includes/Shadow.h"

@interface SHDWRootListController : PSListController
- (void)generate_map:(id)sender;
- (void)support_reddit:(id)sender;
- (void)support_github:(id)sender;
- (void)support_paypal:(id)sender;
- (void)respring:(id)sender;
- (void)reset:(id)sender;
@end
