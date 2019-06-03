#include "SHDWRootListController.h"

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
        NSArray *url_set = [Shadow generateSchemeArray];

        HBPreferences *prefs = [HBPreferences preferencesForIdentifier:BLACKLIST_PATH];

        [prefs setObject:file_map forKey:@"files"];
        [prefs setObject:url_set forKey:@"schemes"];
        
        [alert dismissViewControllerAnimated:YES completion:nil];
    }];
}

- (void)respring:(id)sender {
    [HBRespringController respring];
}

- (void)reset:(id)sender {
    HBPreferences *prefs = [HBPreferences preferencesForIdentifier:PREFS_TWEAK_ID];
    HBPreferences *prefs_apps = [HBPreferences preferencesForIdentifier:APPS_PATH];
    HBPreferences *prefs_blacklist = [HBPreferences preferencesForIdentifier:BLACKLIST_PATH];
    HBPreferences *prefs_tweakcompat = [HBPreferences preferencesForIdentifier:TWEAKCOMPAT_PATH];
    HBPreferences *prefs_injectcompat = [HBPreferences preferencesForIdentifier:INJECTCOMPAT_PATH];
    HBPreferences *prefs_lockdown = [HBPreferences preferencesForIdentifier:LOCKDOWN_PATH];
    HBPreferences *prefs_dlfcn = [HBPreferences preferencesForIdentifier:DLFCN_PATH];

    [prefs removeAllObjects];
    [prefs_apps removeAllObjects];
    [prefs_blacklist removeAllObjects];
    [prefs_tweakcompat removeAllObjects];
    [prefs_injectcompat removeAllObjects];
    [prefs_lockdown removeAllObjects];
    [prefs_dlfcn removeAllObjects];
    
    [self respring:sender];
}
@end
