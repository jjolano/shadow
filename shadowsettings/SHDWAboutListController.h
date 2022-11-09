#import <Foundation/Foundation.h>
#import <Preferences/PSListController.h>
#import <CepheiPrefs/HBListController.h>
#import <Cephei/HBPreferences.h>
#import <Cephei/HBRespringController.h>
#import <HBLog.h>

#import "../api/Shadow.h"
#import "../api/ShadowXPC.h"

@interface SHDWAboutListController : HBListController
- (NSString *)aboutBypassVersion:(id)sender;
- (NSString *)aboutAPIVersion:(id)sender;
- (NSString *)aboutBuildDate:(id)sender;
- (NSString *)aboutSoftwareLicense:(id)sender;
- (NSString *)aboutDeveloper:(id)sender;
@end
