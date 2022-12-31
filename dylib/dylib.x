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

#ifndef kCFCoreFoundationVersionNumber_iOS_11_0
#define kCFCoreFoundationVersionNumber_iOS_11_0 1443.00
#endif

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
    NSString* bundlePath = [bundle bundlePath];

    // Only load Shadow for sandboxed applications.
    // Don't load for App Extensions (.. unless developers are adding detection in those too :/)
    if(![bundle appStoreReceiptURL]
    || [executablePath hasPrefix:@"/Applications"]
    || [executablePath hasPrefix:@"/System"]
    || ![bundlePath hasSuffix:@".app"]) {
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

    // Initialize hooks.
    NSLog(@"%@", @"starting hooks");

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
        [substitutor initLibraries];
    }

    HKBatchHook* hooks = [HKBatchHook new];

    if([prefs_load[@"Hook_Filesystem"] boolValue]) {
        NSLog(@"%@", @"+ filesystem");

        shadowhook_libc(hooks);
        shadowhook_NSFileManager(hooks);
    }

    if([prefs_load[@"Hook_DynamicLibraries"] boolValue]) {
        NSLog(@"%@", @"+ dylib");

        // Register before hooking
        _dyld_register_func_for_add_image(shadowhook_dyld_updatelibs);
        _dyld_register_func_for_remove_image(shadowhook_dyld_updatelibs_r);
        _dyld_register_func_for_add_image(shadowhook_dyld_shdw_add_image);
        _dyld_register_func_for_remove_image(shadowhook_dyld_shdw_remove_image);

        shadowhook_dyld(hooks);
    }

    if([prefs_load[@"Hook_DynamicLibrariesExtra"] boolValue]) {
        NSLog(@"%@", @"+ dylibex");

        shadowhook_dyld_extra(hooks);
    }

    if([prefs_load[@"Hook_URLScheme"] boolValue]) {
        NSLog(@"%@", @"+ urlscheme");

        shadowhook_UIApplication(hooks);
    }

    if([prefs_load[@"Hook_EnvVars"] boolValue]) {
        NSLog(@"%@", @"+ envvars");

        shadowhook_libc_envvar(hooks);
        shadowhook_NSProcessInfo(hooks);
    }

    if([prefs_load[@"Hook_FilesystemExtra"] boolValue]) {
        NSLog(@"%@", @"+ filesystemex");

        shadowhook_libc_extra(hooks);
        shadowhook_NSFileHandle(hooks);
        shadowhook_NSFileVersion(hooks);
        shadowhook_NSFileWrapper(hooks);
    }

    if([prefs_load[@"Hook_Foundation"] boolValue]) {
        NSLog(@"%@", @"+ foundation");

        shadowhook_NSArray(hooks);
        shadowhook_NSDictionary(hooks);
        shadowhook_NSBundle(hooks);
        shadowhook_NSString(hooks);
        shadowhook_NSURL(hooks);
        shadowhook_NSData(hooks);
        shadowhook_UIImage(hooks);
    }

    if([prefs_load[@"Hook_DeviceCheck"] boolValue]) {
        NSLog(@"%@", @"+ devicecheck");

        shadowhook_DeviceCheck(hooks);
    }

    if([prefs_load[@"Hook_MachBootstrap"] boolValue]) {
        NSLog(@"%@", @"+ mach");

        shadowhook_mach(hooks);
    }

    if([prefs_load[@"Hook_SymLookup"] boolValue]) {
        NSLog(@"%@", @"+ dlsym");

        shadowhook_dyld_symlookup(hooks);
    }

    if([prefs_load[@"Hook_LowLevelC"] boolValue]) {
        NSLog(@"%@", @"+ llc");

        shadowhook_libc_lowlevel(hooks);
    }

    if([prefs_load[@"Hook_AntiDebugging"] boolValue]) {
        NSLog(@"%@", @"+ debug");

        shadowhook_libc_antidebugging(hooks);
    }

    if([prefs_load[@"Hook_ObjCRuntime"] boolValue]) {
        NSLog(@"%@", @"+ objc");

        shadowhook_objc(hooks);
    }

    if([prefs_load[@"Hook_FakeMac"] boolValue]) {
        NSLog(@"%@", @"+ m1");

        shadowhook_NSProcessInfo_fakemac(hooks);
    }

    if([prefs_load[@"Hook_Syscall"] boolValue]) {
        NSLog(@"%@", @"+ syscall");

        shadowhook_syscall(hooks);
    }

    if([prefs_load[@"Hook_Sandbox"] boolValue]) {
        NSLog(@"%@", @"+ sandbox");

        shadowhook_sandbox(hooks);
    }

    if([prefs_load[@"Hook_Memory"] boolValue]) {
        NSLog(@"%@", @"+ memory");

        shadowhook_mem(hooks);
    }

    if([prefs_load[@"Hook_TweakClasses"] boolValue]) {
        NSLog(@"%@", @"+ classes");
        
        shadowhook_objc_hidetweakclasses(hooks);
    }

    [hooks performHooksWithSubstitutor:substitutor];

    NSLog(@"%@", @"completed hooks");
}
