#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import "../common.h"
#import <Shadow/JBPath.h>
#import "hooks/hooks.h"
#import "policy/PseudoSandboxPolicy.h"

#import <Shadow.h>
#import <Shadow/Settings.h>
#import <libSandy.h>
#import <HookKit.h>

#include <time.h>

#import "HookCoordinator.h"
#import "../vendor/apple/dyld_priv.h"

// Set by behavioral tripwires in the hook files, never by image-name matching.
BOOL shdw_detector_present = NO;

// Emergency kill-switch for the dyld_all_image_infos memory-hiding patch.
BOOL shdw_memory_hiding_enabled = YES;

static BOOL _shdw_watcher_enabled = NO;
static BOOL _shdw_uikit_installed = NO;
static SHDWHookCoordinator* shdw_coordinator_instance = nil;

// Persist one row per detector category per app launch. Detector hooks can
// fire repeatedly on hot paths; deduping here keeps diagnostics useful and
// avoids turning observation into a new timing fingerprint.
static void shdw_record_detector_event(const char* reason) {
    static dispatch_queue_t queue;
    static NSMutableSet* recordedReasons;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        queue = dispatch_queue_create("me.jjolano.shadow.detector-log", DISPATCH_QUEUE_SERIAL);
        recordedReasons = [NSMutableSet new];
    });

    NSString* reasonString = reason ? [NSString stringWithUTF8String:reason] : @"unknown";
    NSString* bundleID = [NSBundle mainBundle].bundleIdentifier;
    if(reasonString.length == 0 || bundleID.length == 0) {
        return;
    }

    @synchronized(recordedReasons) {
        if([recordedReasons containsObject:reasonString]) {
            return;
        }
        [recordedReasons addObject:reasonString];
    }

    dispatch_async(queue, ^{
        time_t now = time(NULL);
        struct tm localTime;
        char timestamp[20];
        if(!localtime_r(&now, &localTime)
            || strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &localTime) == 0) {
            return;
        }

        NSString* entry = [NSString stringWithFormat:@"%s  %@  %@", timestamp, reasonString, bundleID];
        NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
        NSMutableArray* log = [[defaults arrayForKey:@"DetectorLog"] mutableCopy] ?: [NSMutableArray new];

        // Keep the newest 100 entries in the existing Shadow preferences
        // file. ponytail: cross-process RMW can lose a simultaneous append;
        // move ownership to shadowd only if real log volume makes that matter.
        if(log.count >= 100) {
            [log removeObjectsInRange:NSMakeRange(0, log.count - 99)];
        }
        [log addObject:entry];
        [defaults setObject:log forKey:@"DetectorLog"];
        [defaults synchronize];
    });
}

// UIKit may not exist when the payload is injected at process spawn. Install
// UIKit-class groups only after dyld reports that the framework is loaded.
static void shdw_early_image_add(const struct mach_header* mh, intptr_t vmaddr_slide) {
    (void) vmaddr_slide;

    if(!_shdw_watcher_enabled || _shdw_uikit_installed) {
        return;
    }

    @autoreleasepool {
        const char* path = dyld_image_path_containing_address(mh);

        if(!path || !path[0]) {
            return;
        }

        NSString* image = [[NSString stringWithUTF8String:path] lowercaseString];

        if([image containsString:@"uikit.framework"] && shdw_coordinator_instance) {
            [shdw_coordinator_instance installEvent:SHDWEventUIKitLoaded];
            _shdw_uikit_installed = YES;
        }
    }
}

void shdw_detector_detected(const char* reason) {
    if(!shdw_coordinator_instance) {
        return;
    }

    NSLog(@"[Shadow] detector probe: %s", reason ?: "unknown");
    shdw_record_detector_event(reason);
    shdw_detector_present = YES;

    // The vnode gate re-evaluates its preference and detector state per call.
    shadowhook_vnode(NULL);
    [shdw_coordinator_instance escalateWithReason:reason ? [NSString stringWithUTF8String:reason] : @"unknown"];
}

static void shdw_coord_envvars_c(HKSubstitutor* hooks) {
    NSProcessInfo* procInfo = [NSProcessInfo processInfo];
    NSDictionary* procEnv = [procInfo environment];
    NSArray* safeEnvvars = @[
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
        if(![safeEnvvars containsObject:envvar]) {
            NSLog(@"+ removing envvar: %@", envvar);
            unsetenv([envvar UTF8String]);
        }
    }

    setenv("SHELL", "/bin/sh", 1);
    shadowhook_libc_envvar(hooks);
    shadowhook_envpolicy(hooks);
}

static void shdw_coord_symlookup(HKSubstitutor* hooks) {
    shadowhook_dyld_symlookup(hooks);
    shadowhook_dyld_symaddrlookup(hooks);
}

static void shdw_coord_verify_symlookup(void) {
    shadowhook_dyld_symlookup_verify();
    shadowhook_dyld_symaddrlookup_verify();
}

static void shdw_coord_filesystem_objc(HKSubstitutor* hooks) {
    shadowhook_NSFileManager(hooks);
    shadowhook_NSFileHandle(hooks);
    shadowhook_NSFileVersion(hooks);
    shadowhook_NSFileWrapper(hooks);
}

static void shdw_coord_foundation_objc(HKSubstitutor* hooks) {
    shadowhook_NSArray(hooks);
    shadowhook_NSDictionary(hooks);
    shadowhook_NSBundle(hooks);
    shadowhook_NSString(hooks);
    shadowhook_NSURL(hooks);
    shadowhook_NSData(hooks);
    shadowhook_NSThread(hooks);
    shadowhook_NSUserDefaults(hooks);
    shadowhook_NSTask(hooks);
}

// Must stay in SHDWInstallUnits() order.
static const SHDWHookInstaller kSHDWCoordinatorInstallers[] = {
    { "dyld",                         shadowhook_dyld,                 shadowhook_dyld_verify },
    { "Hook_Filesystem@c",            shadowhook_libc,                 shadowhook_libc_verify },
    { "Hook_EnvVars@c",               shdw_coord_envvars_c,            shadowhook_libc_envvar_verify },
    { "Hook_EnvVars@objc",            shadowhook_NSProcessInfo,        NULL },
    { "Hook_DeviceCheck",             shadowhook_DeviceCheck,          NULL },
    { "Hook_MachBootstrap",           shadowhook_mach,                 shadowhook_mach_verify },
    { "Hook_IOKit",                   shadowhook_iokit,                shadowhook_iokit_verify },
    { "Hook_LowLevelC",               shadowhook_libc_lowlevel,        shadowhook_libc_lowlevel_verify },
    { "Hook_AntiDebugging",           shadowhook_libc_antidebugging,   shadowhook_libc_antidebugging_verify },
    { "objc",                         shadowhook_objc,                 NULL },
    { "objc@methodimpl",              shadowhook_objc_methodimpl,      NULL },
    { "Hook_Syscall",                 shadowhook_syscall,              shadowhook_syscall_verify },
    { "Hook_Memory",                  shadowhook_mem,                  shadowhook_mem_verify },
    { "Hook_Sandbox",                 shadowhook_sandbox,              shadowhook_sandbox_verify },
    { "classes",                      shadowhook_objc_hidetweakclasses, NULL },
    { "symlookup",                    shdw_coord_symlookup,            shdw_coord_verify_symlookup },
    { "Hook_DynamicLibrariesExtra",   shadowhook_dyld_extra,           shadowhook_dyld_extra_verify },
    { "Hook_Filesystem@objc",         shdw_coord_filesystem_objc,      NULL },
    { "Hook_Foundation@objc",         shdw_coord_foundation_objc,      NULL },
    { "Hook_HideApps",                shadowhook_LSApplicationWorkspace, NULL },
    { "Hook_URLScheme",               shadowhook_UIApplication,        NULL },
    { "Hook_Foundation@uikit",        shadowhook_UIImage,              NULL },
};

static void shdw_coordinator_ctor(NSDictionary<NSString*, id>* prefs) {
    shdw_coordinator_instance =
        [[SHDWHookCoordinator alloc] initWithInstallerTable:kSHDWCoordinatorInstallers
                                                      count:sizeof(kSHDWCoordinatorInstallers) / sizeof(kSHDWCoordinatorInstallers[0])
                                                      prefs:prefs];

    if(shdw_coordinator_instance) {
        [shdw_coordinator_instance installEvent:SHDWEventCtor];
    } else {
        NSLog(@"[Shadow][coordinator] init failed — continuing unhooked");
    }
}

%ctor {
    @try {
        // Registration replays current images while the watcher is disabled;
        // they are replayed once more after preferences and hooks are ready.
        _dyld_register_func_for_add_image(shdw_early_image_add);

        NSString* bundleIdentifier = [NSBundle mainBundle].bundleIdentifier;

        if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_11_0) {
            libSandy_applyProfile("ShadowSettings");
        }

        NSDictionary* prefs = [[ShadowSettings sharedInstance] getPreferencesForIdentifier:bundleIdentifier];

        if(!prefs) {
            NSLog(@"[Shadow] warning: preferences not loaded");
            return;
        }

        NSLog(@"%@", prefs);

        if(![prefs[@"App_Enabled"] boolValue]) {
            return;
        }

        shdw_memory_hiding_enabled = [prefs[@"MemoryLevelHiding"] boolValue];

        [Shadow sharedInstance];
        shdw_own_ranges_refresh();
        shdw_pseudo_init(prefs);

        shdw_vnode_set_pref_enabled([prefs[@"VnodeHiding"] boolValue]);
        shadowhook_vnode(NULL);

        NSLog(@"starting hooks");
        [Shadow shdwEnterInternalRead];
        @try {
            shdw_coordinator_ctor(prefs);
        } @finally {
            [Shadow shdwExitInternalRead];
        }

        _shdw_watcher_enabled = shdw_coordinator_instance
            && (shdw_coordinator_instance.backends.capabilities & SHDWCapMessage)
            && ([prefs[@"Hook_URLScheme"] boolValue] || [prefs[@"Hook_Foundation"] boolValue]);

        if(_shdw_watcher_enabled) {
            uint32_t count = _dyld_image_count();

            for(uint32_t i = 0; i < count; i++) {
                shdw_early_image_add(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
            }
        }
    } @catch (NSException* e) {
        NSLog(@"[Shadow] constructor failed: %@ — continuing unhooked", e);
        return;
    }

    NSString* counterKey = shdw_crash_counter_key();
    if(counterKey) {
        NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
        [defaults removeObjectForKey:counterKey];
        [defaults synchronize];
    }

    NSLog(@"completed hooks");
}

%dtor {
    shadowhook_vnode_release();
}
