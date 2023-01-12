#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import "../api/common.h"
#import "../api/rootless.h"
#import "../api/Shadow.h"
#import "../api/ShadowService.h"

#import "../api/ShadowService+Settings.h"
#import "../api/ShadowService+Database.h"

#import "hooks/hooks.h"

#import <libSandy.h>
#import <HookKit.h>

Shadow* _shadow = nil;
ShadowService* _srv = nil;

%group hook_springboard
%hook SpringBoard
- (void)applicationDidFinishLaunching:(UIApplication *)application {
    %orig;

    _srv = [ShadowService new];
    [_srv startService];

    NSOperationQueue* queue = [NSOperationQueue new];

    [queue addOperationWithBlock:^(){
        NSDictionary* ruleset_dpkg = [ShadowService generateDatabase];

        if(ruleset_dpkg) {
            [_srv addRuleset:ruleset_dpkg];

            BOOL success = [ruleset_dpkg writeToFile:@SHADOW_DB_PLIST atomically:NO];

            if(!success) {
                success = [ruleset_dpkg writeToFile:@("/var/jb" SHADOW_DB_PLIST) atomically:NO];
            }

            if(success) {
                NSLog(@"%@", @"successfully saved generated db");
            } else {
                NSLog(@"%@", @"failed to save generate db");
            }
        }
    }];
}
%end
%end

%ctor {
    // Determine the application we're injected into.
    NSBundle* bundle = [NSBundle mainBundle];
    NSString* bundleIdentifier = [bundle bundleIdentifier];

    // Injected into SpringBoard.
    if([bundleIdentifier isEqualToString:@"com.apple.springboard"]) {
        NSLog(@"%@", @"loaded in SpringBoard");
        %init(hook_springboard);		
        return;
    }

    NSString* executablePath = [bundle executablePath];

    // Only load Shadow for sandboxed applications.
    // Don't load for App Extensions (.. unless developers are adding detection in those too :/)
    if(![bundle appStoreReceiptURL]
    || [executablePath hasPrefix:@"/Applications"]
    || [executablePath hasPrefix:@"/System"]
    || ![[[executablePath stringByDeletingLastPathComponent] pathExtension] isEqualToString:@"app"]) {
        return;
    }

    NSLog(@"%@", @"loaded in app");

    libSandy_applyProfile("ShadowService");

    _srv = [ShadowService new];
    [_srv connectService];

    // Load preferences.
    NSDictionary* prefs_load = nil;

    if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_11_0) {
        libSandy_applyProfile("ShadowSettings");
        prefs_load = [ShadowService getPreferences:bundleIdentifier];
    }

    if(!prefs_load) {
        // Use Shadow Service to load preferences.
        prefs_load = [ShadowService getPreferences:bundleIdentifier usingService:_srv];
    }

    NSLog(@"%@", prefs_load);

    BOOL enabled = [prefs_load[@"App_Enabled"] boolValue];

    if(!enabled) {
        return;
    }

    // Initialize Shadow class.
    [_srv loadRulesets];

    _shadow = [Shadow shadowWithService:_srv];

    [_shadow setTweakCompatibility:[prefs_load[@"Tweak_CompatEx"] boolValue]];
    [_shadow setRootlessMode:[prefs_load[@"Rootless"] boolValue]];

    // Initialize hooks.
    NSLog(@"%@", @"starting hooks");

    #ifdef hookkit_h
    hookkit_lib_t hooklibs = HK_LIB_NONE;
    
    if(prefs_load[@"HK_Library"]) {
        hookkit_lib_t hooklibs_available_types = [HKSubstitutor getAvailableSubstitutorTypes];
        NSArray<NSDictionary *>* hooklibs_available_info = [HKSubstitutor getSubstitutorTypeInfo:hooklibs_available_types];

        for(NSDictionary* hooklib_info in hooklibs_available_info) {
            if([prefs_load[@"HK_Library"] isEqualToString:hooklib_info[@"id"]]) {
                hookkit_lib_t type = (hookkit_lib_t)[hooklib_info[@"type"] unsignedIntValue];

                if(hooklibs_available_types & type) {
                    hooklibs = type;
                }

                break;
            }
        }
    }

    HKSubstitutor* substitutor = [HKSubstitutor defaultSubstitutor];

    if(hooklibs != HK_LIB_NONE) {
        [substitutor setTypes:hooklibs];
    }

    [substitutor initLibraries];
    
    HKEnableBatching();
    #else
    HKSubstitutor* substitutor = NULL;
    #endif

    if([prefs_load[@"Hook_Filesystem"] boolValue]) {
        NSLog(@"%@", @"+ filesystem");

        shadowhook_libc(substitutor);
        shadowhook_NSFileManager(substitutor);
    }

    if([prefs_load[@"Hook_DynamicLibraries"] boolValue]) {
        NSLog(@"%@", @"+ dylib");

        // Register before hooking
        _dyld_register_func_for_add_image(shadowhook_dyld_updatelibs);
        _dyld_register_func_for_remove_image(shadowhook_dyld_updatelibs_r);
        _dyld_register_func_for_add_image(shadowhook_dyld_shdw_add_image);
        _dyld_register_func_for_remove_image(shadowhook_dyld_shdw_remove_image);

        shadowhook_dyld(substitutor);
    }

    if([prefs_load[@"Hook_URLScheme"] boolValue]) {
        NSLog(@"%@", @"+ urlscheme");

        shadowhook_UIApplication(substitutor);
    }

    if([prefs_load[@"Hook_EnvVars"] boolValue]) {
        NSLog(@"%@", @"+ envvars");

        shadowhook_libc_envvar(substitutor);
        shadowhook_NSProcessInfo(substitutor);
    }

    if([prefs_load[@"Hook_FilesystemExtra"] boolValue]) {
        NSLog(@"%@", @"+ filesystemex");

        shadowhook_libc_extra(substitutor);
        shadowhook_NSFileHandle(substitutor);
        shadowhook_NSFileVersion(substitutor);
        shadowhook_NSFileWrapper(substitutor);
    }

    if([prefs_load[@"Hook_Foundation"] boolValue]) {
        NSLog(@"%@", @"+ foundation");

        shadowhook_NSArray(substitutor);
        shadowhook_NSDictionary(substitutor);
        shadowhook_NSBundle(substitutor);
        shadowhook_NSString(substitutor);
        shadowhook_NSURL(substitutor);
        shadowhook_NSData(substitutor);
        shadowhook_UIImage(substitutor);
    }

    if([prefs_load[@"Hook_DeviceCheck"] boolValue]) {
        NSLog(@"%@", @"+ devicecheck");

        shadowhook_DeviceCheck(substitutor);
    }

    if([prefs_load[@"Hook_MachBootstrap"] boolValue]) {
        NSLog(@"%@", @"+ mach");

        shadowhook_mach(substitutor);
    }

    if([prefs_load[@"Hook_LowLevelC"] boolValue]) {
        NSLog(@"%@", @"+ llc");

        shadowhook_libc_lowlevel(substitutor);
    }

    if([prefs_load[@"Hook_AntiDebugging"] boolValue]) {
        NSLog(@"%@", @"+ debug");

        shadowhook_libc_antidebugging(substitutor);
    }

    if([prefs_load[@"Hook_ObjCRuntime"] boolValue]) {
        NSLog(@"%@", @"+ objc");

        shadowhook_objc(substitutor);
    }

    if([prefs_load[@"Hook_FakeMac"] boolValue]) {
        NSLog(@"%@", @"+ m1");

        shadowhook_NSProcessInfo_fakemac(substitutor);
    }

    if([prefs_load[@"Hook_Syscall"] boolValue]) {
        NSLog(@"%@", @"+ syscall");

        shadowhook_syscall(substitutor);
    }

    if([prefs_load[@"Hook_Memory"] boolValue]) {
        NSLog(@"%@", @"+ memory");

        shadowhook_mem(substitutor);
    }

    if([prefs_load[@"Hook_HideApps"] boolValue]) {
        NSLog(@"%@", @"+ apps");

        shadowhook_LSApplicationWorkspace(substitutor);
    }

    if([prefs_load[@"Hook_Sandbox"] boolValue]) {
        NSLog(@"%@", @"+ sandbox");

        shadowhook_sandbox(substitutor);
    }

    if([prefs_load[@"Hook_TweakClasses"] boolValue]) {
        NSLog(@"%@", @"+ classes");
        
        shadowhook_objc_hidetweakclasses(substitutor);
    }

    if([prefs_load[@"Hook_SymLookup"] boolValue]) {
        NSLog(@"%@", @"+ dlsym");

        shadowhook_dyld_symlookup(substitutor);
        shadowhook_dyld_symaddrlookup(substitutor);
    }

    #ifdef hookkit_h
    HKExecuteBatch();
    HKDisableBatching();
    #endif

    if([prefs_load[@"Hook_DynamicLibrariesExtra"] boolValue]) {
        NSLog(@"%@", @"+ dylibex");

        shadowhook_dyld_extra(substitutor);
    }

    NSLog(@"%@", @"completed hooks");
}
