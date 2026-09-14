#import <Foundation/Foundation.h>
#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>

@interface SHDWAboutListController : PSListController
- (NSString *)aboutDeveloper:(id)sender;
- (NSString *)aboutTranslator:(id)sender;
- (NSString *)aboutInstalledVersion:(id)sender;

- (void)openGitHub:(id)sender;
- (void)openKofi:(id)sender;
- (void)resetSettings:(id)sender;
@end
