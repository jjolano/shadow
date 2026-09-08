#import <Foundation/Foundation.h>
#import <Preferences/PSSpecifier.h>
#import <Preferences/PSListController.h>

@interface SHDWAboutListController : PSListController
- (NSString *)aboutDeveloper:(id)sender;
- (NSString *)aboutTranslator:(id)sender;
- (NSString *)aboutInstalledVersion:(id)sender;

- (void)openGitHub:(id)sender;
- (void)openKofi:(id)sender;
- (void)resetSettings:(id)sender;
@end
