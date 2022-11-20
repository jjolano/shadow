#import <Foundation/Foundation.h>
#import <Preferences/PSListController.h>
#import <CepheiPrefs/HBListController.h>
#import <Cephei/HBPreferences.h>
#import <HBLog.h>

#import "../apple_priv/NSTask.h"

#import "../api/Shadow.h"
#import "../api/ShadowService.h"


@interface SHDWAboutListController : HBListController
- (NSString *)aboutBypassVersion:(id)sender;
- (NSString *)aboutAPIVersion:(id)sender;
- (NSString *)aboutBuildDate:(id)sender;
- (NSString *)aboutSoftwareLicense:(id)sender;
- (NSString *)aboutDeveloper:(id)sender;
- (NSString *)aboutPackageVersion:(id)sender;
- (NSString *)aboutLatestVersion:(id)sender;
@end
