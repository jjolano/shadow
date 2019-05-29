#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include "SHDWRootListController.h"
#include "../Includes/Shadow.h"

@implementation SHDWRootListController

- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [[self loadSpecifiersFromPlistName:@"Root" target:self] retain];
    }

    return _specifiers;
}

- (void)support_reddit:(id)sender {
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://www.reddit.com/r/jailbreak/comments/bp59zs/release_shadow_a_simple_open_source_jailbreak/"]];
}

- (void)support_github:(id)sender {
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/jjolano/shadow"]];
}

- (void)support_paypal:(id)sender {
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://paypal.me/jjolano"]];
}

- (void)generate_map:(id)sender {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Shadow" message:@"Processing packages..." preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:alert animated:YES completion:^{
        NSArray *file_map = [Shadow generateFileMap];

        NSMutableDictionary *prefs = [[NSMutableDictionary alloc] initWithContentsOfFile:PREFS_PATH];

        if(prefs) {
            [prefs setValue:file_map forKey:@"file_map"];
            [prefs writeToFile:PREFS_PATH atomically:YES];
        }
        
        [alert dismissViewControllerAnimated:YES completion:nil];
    }];
}

@end
