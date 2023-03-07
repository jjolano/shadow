#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import "../common.h"
#import "hooks/hooks.h"

#import <Shadow.h>
#import <Shadow/Settings.h>
#import <libSandy.h>
#import <HookKit.h>

Shadow* _shadow = nil;

%ctor {
    // Determine the application we're injected into.
    NSString* bundleIdentifier = [Shadow getBundleIdentifier];

    // Injected into SpringBoard.
    if([bundleIdentifier isEqualToString:@"com.apple.springboard"]) {
        return;
    }

    NSString* executablePath = [Shadow getExecutablePath];
    NSString* bundleType = [[executablePath stringByDeletingLastPathComponent] pathExtension];

    // Only load Shadow for applications in /var.
    if(![bundleType isEqualToString:@"app"]) {
        return;
    }

    if([executablePath hasPrefix:@"/Applications"]
    || [executablePath hasPrefix:@"/System"]
    || [executablePath hasPrefix:@"/private/preboot"]
    || [executablePath hasPrefix:@"/var/jb"]) {
        return;
    }

    if(![[NSBundle mainBundle] appStoreReceiptURL]) {
        return;
    }

    // Don't load in certain apps
    if([bundleIdentifier isEqualToString:@"com.opa334.TrollStore"]
    || [bundleIdentifier hasPrefix:@"com.apple"]) {
        return;
    }

    NSLog(@"%@", @"loaded in app");

    // Load preferences.
    if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_11_0) {
        libSandy_applyProfile("ShadowSettings");
    }

    NSDictionary* prefs_load = [[ShadowSettings sharedInstance] getPreferencesForIdentifier:bundleIdentifier];

    NSLog(@"%@", prefs_load);

    BOOL enabled = [prefs_load[@"App_Enabled"] boolValue];

    if(!enabled) {
        return;
    }

    // Initialize Shadow class.
    _shadow = [Shadow new];

    // Initialize hooks.
    NSLog(@"%@", @"starting hooks");

    #ifdef hookkit_h
    hookkit_lib_t hooklibs = HK_LIB_NONE;
    
    if(prefs_load[@"HK_Library"] && ![prefs_load[@"HK_Library"] isEqualToString:@"auto"]) {
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
    
    HKEnableBatching();
    #else
    HKSubstitutor* substitutor = NULL;
    #endif

    if([prefs_load[@"Hook_DynamicLibraries"] boolValue]) {
        NSLog(@"%@", @"+ dylib");
        
        shadowhook_dyld(substitutor);
    }

    if([prefs_load[@"Hook_Filesystem"] boolValue]) {
        NSLog(@"%@", @"+ filesystem");

        shadowhook_libc(substitutor);
        shadowhook_NSFileManager(substitutor);
        shadowhook_NSFileHandle(substitutor);
        shadowhook_NSFileVersion(substitutor);
        shadowhook_NSFileWrapper(substitutor);
    }

    if([prefs_load[@"Hook_URLScheme"] boolValue]) {
        NSLog(@"%@", @"+ urlscheme");

        shadowhook_UIApplication(substitutor);
    }

    if([prefs_load[@"Hook_EnvVars"] boolValue]) {
        NSLog(@"%@", @"+ envvars");

        unsetenv("DYLD_INSERT_LIBRARIES");
        unsetenv("_MSSafeMode");
        unsetenv("_SafeMode");
        unsetenv("_SubstituteSafeMode");
        setenv("SHELL", "/bin/sh", 1);

        shadowhook_libc_envvar(substitutor);
        shadowhook_NSProcessInfo(substitutor);
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
        shadowhook_NSThread(substitutor);
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

    if([prefs_load[@"Hook_DynamicLibrariesExtra"] boolValue]) {
        NSLog(@"%@", @"+ dylibex");

        shadowhook_dyld_extra(substitutor);
    }

    #ifdef hookkit_h
    HKExecuteBatch();
    HKDisableBatching();
    #endif

    NSLog(@"%@", @"completed hooks");
}
