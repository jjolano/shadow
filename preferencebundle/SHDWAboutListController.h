#import <Foundation/Foundation.h>
#import <Preferences/PSListController.h>
#import <HBLog.h>

#import "../apple_priv/NSTask.h"

#import "../api/Shadow.h"
#import "../api/ShadowService.h"


@interface SHDWAboutListController : PSListController
- (NSString *)aboutBypassVersion:(id)sender;
- (NSString *)aboutAPIVersion:(id)sender;
- (NSString *)aboutBuildDate:(id)sender;
- (NSString *)aboutSoftwareLicense:(id)sender;
- (NSString *)aboutDeveloper:(id)sender;
- (NSString *)aboutPackageVersion:(id)sender;
- (NSString *)aboutLatestVersion:(id)sender;

- (void)openGitHub:(id)sender;
- (void)openKofi:(id)sender;
@end
