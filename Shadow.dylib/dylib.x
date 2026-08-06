#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import "../common.h"
#import "hooks/hooks.h"

#import <Shadow.h>
#import <Shadow/Settings.h>
#import <libSandy.h>
#import <HookKit.h>
#import <RootBridge.h>

// Set when a known detection library is loaded (see %ctor); consumed by
// dyld.x (memory-hiding escalation) and by the hook-backend routing below.
BOOL shdw_detector_present = NO;

%ctor {
    // Detector-presence detection, run before prefs loading and before any
    // hook installation: dyld APIs are still unhooked here, so the real
    // image list is visible. When IOSSecuritySuite (image name
    // "iossecuritysuite") or freeRASP (ships as TalsecRuntime.xcframework,
    // binary "TalsecRuntime" → matched via "talsec"; legacy "freerasp" kept
    // for older builds) is loaded we escalate (stealth routing + memory
    // hiding) regardless of preferences.
    uint32_t image_count = _dyld_image_count();

    for(uint32_t i = 0; i < image_count; i++) {
        const char* image_name = _dyld_get_image_name(i);

        if(image_name) {
            NSString* image_lower = [[NSString stringWithUTF8String:image_name] lowercaseString];

            if([image_lower containsString:@"iossecuritysuite"] || [image_lower containsString:@"freerasp"] || [image_lower containsString:@"talsec"]) {
                shdw_detector_present = YES;
                NSLog(@"[Shadow] detection library present: %s", image_name);
                break;
            }
        }
    }

    // Determine the application we're injected into.
    NSString* bundleIdentifier = [Shadow getBundleIdentifier];

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

    // Don't load in certain apps
    if([bundleIdentifier hasPrefix:@"com.opa334"]
    || [bundleIdentifier hasPrefix:@"org.coolstar"]
    || [bundleIdentifier hasPrefix:@"science.xnu"]
    || [bundleIdentifier hasPrefix:@"com.apple"]
    || [bundleIdentifier hasPrefix:@"com.samiiau.loader"]
    || [bundleIdentifier hasPrefix:@"com.llsc12.palera1nLoader"]) {
        return;
    }

    NSLog(@"loaded in app");

    // Load preferences.
    if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_11_0) {
        libSandy_applyProfile("ShadowSettings");
    }

    NSDictionary* prefs_load = [[ShadowSettings sharedInstance] getPreferencesForIdentifier:bundleIdentifier];

    if(!prefs_load) {
        NSLog(@"[Shadow] warning: preferences not loaded");
        return;
    }

    NSLog(@"%@", prefs_load);

    BOOL enabled = [prefs_load[@"App_Enabled"] boolValue];

    if(!enabled) {
        return;
    }

    // Initialize Shadow instance.
    [Shadow sharedInstance];

    // Initialize hooks.
    NSLog(@"starting hooks");

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

    // subMain: current behavior preserved — default substitutor, HK_Library
    // pref overrides as before. Used for ObjC-method hooks (fishhook can't
    // swizzle methods) and as the fallback for every other group.
    HKSubstitutor* subMain = [HKSubstitutor defaultSubstitutor];

    if(hooklibs != HK_LIB_NONE) {
        [subMain setTypes:hooklibs];
        [subMain initLibraries];
    }

    // subFish: fishhook backend. Rebinds pointer-table slots only — function
    // prologues stay untouched, so amIMSHooked-style prologue scans see
    // nothing. C-function hooks that detectors call route through this.
    HKSubstitutor* subFish = ([HKSubstitutor getAvailableSubstitutorTypes] & HK_LIB_FISHHOOK) ? [HKSubstitutor substitutorWithTypes:HK_LIB_FISHHOOK] : NULL;

    // subInline: ElleKit (inline) backend. Installs trampolines in function
    // prologues (ldr x16, #imm; br x16), so amIMSHooked-style prologue
    // scanners can spot them — but denyFishHook("dladdr") cannot un-rebind
    // inline hooks, and fishhook can't reach private symbols like
    // dlopen_internal. Used for dlopen_internal always, and for dlsym/dladdr
    // only when a detection library is present.
    HKSubstitutor* subInline = ([HKSubstitutor getAvailableSubstitutorTypes] & HK_LIB_ELLEKIT) ? [HKSubstitutor substitutorWithTypes:HK_LIB_ELLEKIT] : NULL;

    // C-function groups: subFish when available, else subMain. Escalation:
    // with a detection library present, stealth beats the HK_Library pref —
    // C groups stay on fishhook even if the pref selected ElleKit.
    HKSubstitutor* subCFunc = subFish ? subFish : subMain;

    // dlsym/dladdr group: fishhook by default — clean prologues, so
    // amIMSHooked-style prologue scanners see nothing. Tradeoff: fishhook is
    // revertible via IOSSecuritySuite's denyFishHook("dladdr"), so escalate
    // to inline (prologue-detectable but denyFishHook-immune) only when a
    // detection library is present.
    HKSubstitutor* subSymLookup = shdw_detector_present ? (subInline ? subInline : subMain) : subCFunc;

    // dlopen_internal is a private libdyld symbol fishhook can't rebind:
    // inline only, always (never fishhook — see subInline comment).
    HKSubstitutor* subDyldExtra = subInline ? subInline : subMain;

    // Batching must be enabled per instance; the HK*Batching macros below
    // only touch the default substitutor (subMain).
    [subMain setBatching:YES];
    [subFish setBatching:YES];
    [subInline setBatching:YES];
    HKEnableBatching();
    #else
    HKSubstitutor* subMain = NULL;
    HKSubstitutor* subCFunc = NULL;
    HKSubstitutor* subSymLookup = NULL;
    HKSubstitutor* subDyldExtra = NULL;
    #endif

    if([prefs_load[@"Hook_DynamicLibraries"] boolValue]) {
        NSLog(@"+ dylib");
        
        shadowhook_dyld(subCFunc);
    }

    if([prefs_load[@"Hook_Filesystem"] boolValue]) {
        NSLog(@"+ filesystem");

        shadowhook_libc(subCFunc);
        shadowhook_NSFileManager(subMain);
        shadowhook_NSFileHandle(subMain);
        shadowhook_NSFileVersion(subMain);
        shadowhook_NSFileWrapper(subMain);
    }

    if([prefs_load[@"Hook_URLScheme"] boolValue]) {
        NSLog(@"+ urlscheme");

        shadowhook_UIApplication(subMain);
    }

    if([prefs_load[@"Hook_EnvVars"] boolValue]) {
        NSLog(@"+ envvars");

        NSProcessInfo* procInfo = [NSProcessInfo processInfo];
        NSDictionary* procEnv = [procInfo environment];

        NSArray* safe_envvars = @[
            @"CFFIXED_USER_HOME",
            @"HOME",
            @"LOGNAME",
            @"PATH",
            @"SHELL",
            @"TMPDIR",
            @"USER",
            @"XPC_FLAGS",
            @"XPC_SERVICE_NAME",
            @"__CF_USER_TEXT_ENCODING"
        ];

        for(NSString* envvar in procEnv) {
            if(![safe_envvars containsObject:envvar]) {
                NSLog(@"+ removing envvar: %@", envvar);
                unsetenv([envvar UTF8String]);
            }
        }

        // unsetenv("DYLD_INSERT_LIBRARIES");
        // unsetenv("_MSSafeMode");
        // unsetenv("_SafeMode");
        // unsetenv("_SubstituteSafeMode");
        // unsetenv("JSC_useGC");
        // unsetenv("JSC_useDollarVM");
        // unsetenv("JAILBREAKD_PATH");
        // unsetenv("JAILBREAKD_ARG");
        // unsetenv("JAILBREAKD_CDHASH");

        setenv("SHELL", "/bin/sh", 1);

        // shadowhook_libc_envvar(subMain);
        // shadowhook_NSProcessInfo(substitutor);
    }

    if([prefs_load[@"Hook_Foundation"] boolValue]) {
        NSLog(@"+ foundation");

        shadowhook_NSArray(subMain);
        shadowhook_NSDictionary(subMain);
        shadowhook_NSBundle(subMain);
        shadowhook_NSString(subMain);
        shadowhook_NSURL(subMain);
        shadowhook_NSData(subMain);
        shadowhook_UIImage(subMain);
        shadowhook_NSThread(subMain);
    }

    if([prefs_load[@"Hook_DeviceCheck"] boolValue]) {
        NSLog(@"+ devicecheck");

        shadowhook_DeviceCheck(subCFunc);
    }

    if([prefs_load[@"Hook_MachBootstrap"] boolValue]) {
        NSLog(@"+ mach");

        shadowhook_mach(subCFunc);
    }

    if([prefs_load[@"Hook_LowLevelC"] boolValue]) {
        NSLog(@"+ llc");

        shadowhook_libc_lowlevel(subCFunc);
    }

    if([prefs_load[@"Hook_AntiDebugging"] boolValue]) {
        NSLog(@"+ debug");

        shadowhook_libc_antidebugging(subCFunc);
    }

    if([prefs_load[@"Hook_ObjCRuntime"] boolValue]) {
        NSLog(@"+ objc");

        // libobjc C functions (objc_copyImageNames etc.) are exported symbols
        // fishhook could rebind, but the runtime calls some of them directly
        // in hot paths — keep them inline via subMain to be safe.
        shadowhook_objc(subMain);
    }

    if([prefs_load[@"Hook_FakeMac"] boolValue]) {
        NSLog(@"+ m1");

        shadowhook_NSProcessInfo_fakemac(subMain);
    }

    if([prefs_load[@"Hook_Syscall"] boolValue]) {
        NSLog(@"+ syscall");

        shadowhook_syscall(subCFunc);
    }

    if([prefs_load[@"Hook_Memory"] boolValue]) {
        NSLog(@"+ memory");

        shadowhook_mem(subCFunc);
    }

    if([prefs_load[@"Hook_HideApps"] boolValue]) {
        NSLog(@"+ apps");

        shadowhook_LSApplicationWorkspace(subMain);
    }

    if([prefs_load[@"Hook_Sandbox"] boolValue]) {
        NSLog(@"+ sandbox");

        shadowhook_sandbox(subCFunc);
    }

    if([prefs_load[@"Hook_TweakClasses"] boolValue]) {
        NSLog(@"+ classes");
        
        // Same reasoning as shadowhook_objc above: C-function hooks in the
        // runtime path stay on subMain.
        shadowhook_objc_hidetweakclasses(subMain);
    }

    if([prefs_load[@"Hook_SymLookup"] boolValue]) {
        NSLog(@"+ dlsym");

        // dlsym/dladdr: fishhook keeps prologues clean; escalates to inline
        // (denyFishHook-immune) when a detection library is present.
        shadowhook_dyld_symlookup(subSymLookup);
        shadowhook_dyld_symaddrlookup(subSymLookup);
    }

    if([prefs_load[@"Hook_DynamicLibrariesExtra"] boolValue]) {
        NSLog(@"+ dylibex");

        // dlopen_internal is a private libdyld symbol fishhook can't rebind —
        // inline only, always.
        shadowhook_dyld_extra(subDyldExtra);
    }

    #ifdef hookkit_h
    [subFish executeHooks];
    [subFish setBatching:NO];
    [subInline executeHooks];
    [subInline setBatching:NO];
    HKExecuteBatch();
    HKDisableBatching();
    #endif

    NSLog(@"completed hooks");
}
