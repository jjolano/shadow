#include "SHDWRootListController.h"

@implementation SHDWRootListController

- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [[self loadSpecifiersFromPlistName:@"Root" target:self] retain];
    }

    return _specifiers;
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
    // Use sbreload if available.
    if([[NSFileManager defaultManager] fileExistsAtPath:@"/usr/bin/sbreload"]) {
        pid_t pid;
        const char *args[] = {"sbreload", NULL, NULL, NULL};
        posix_spawn(&pid, "/usr/bin/sbreload", NULL, NULL, (char *const *)args, NULL);
    } else {
        [HBRespringController respring];
    }
}

- (void)reset:(id)sender {
    HBPreferences *prefs = [HBPreferences preferencesForIdentifier:PREFS_TWEAK_ID];
    HBPreferences *prefs_apps = [HBPreferences preferencesForIdentifier:APPS_PATH];
    HBPreferences *prefs_blacklist = [HBPreferences preferencesForIdentifier:BLACKLIST_PATH];
    HBPreferences *prefs_tweakcompat = [HBPreferences preferencesForIdentifier:TWEAKCOMPAT_PATH];
    HBPreferences *prefs_lockdown = [HBPreferences preferencesForIdentifier:LOCKDOWN_PATH];
    HBPreferences *prefs_dlfcn = [HBPreferences preferencesForIdentifier:DLFCN_PATH];

    if(prefs) {
        [prefs removeAllObjects];
    }

    if(prefs_apps) {
        [prefs_apps removeAllObjects];
    }

    if(prefs_blacklist) {
        [prefs_blacklist removeAllObjects];
    }

    if(prefs_tweakcompat) {
        [prefs_tweakcompat removeAllObjects];
    }
    
    if(prefs_lockdown) {
        [prefs_lockdown removeAllObjects];
    }

    if(prefs_dlfcn) {
        [prefs_dlfcn removeAllObjects];
    }
    
    [self respring:sender];
}
@end
