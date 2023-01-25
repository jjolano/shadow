#import <Foundation/Foundation.h>
#import <Preferences/PSListController.h>

@interface SHDWAboutListController : PSListController
- (NSString *)aboutBuildDate:(id)sender;
- (NSString *)aboutSoftwareLicense:(id)sender;
- (NSString *)aboutDeveloper:(id)sender;
- (NSString *)aboutTranslator:(id)sender;
- (NSString *)aboutLatestVersion:(id)sender;

- (void)openGitHub:(id)sender;
- (void)openKofi:(id)sender;
- (void)openChangeLog:(id)sender;
@end
