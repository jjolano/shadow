#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import "../common.h"
#import <Shadow/JBPath.h>
#import "hooks/hooks.h"
#import "policy/PathPolicy.h"
#import "policy/PseudoSandboxPolicy.h"

#import <Shadow.h>
#import <Shadow/Settings.h>
#import <libSandy.h>

#include <time.h>
#include <dlfcn.h>
#include <mach/mach.h>

#import "HookCoordinator.h"
#import "../vendor/apple/dyld_priv.h"

// Set by an exact detector-adapter match or behavioral tripwires.
BOOL shdw_detector_present = NO;

// Emergency kill-switch for the dyld_all_image_infos memory-hiding patch.
BOOL shdw_memory_hiding_enabled = YES;

static BOOL _shdw_watcher_enabled = NO;
static BOOL _shdw_uikit_installed = NO;
static SHDWHookCoordinator* shdw_coordinator_instance = nil;

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
    (void) reason;

    if(!shdw_coordinator_instance) {
        return;
    }

    shdw_detector_present = YES;
    shdw_detector_write_policy_set_enabled(YES);
    [shdw_coordinator_instance escalateWithReason:nil];
}

static void shdw_coord_envvars_c(SHDWHookSession* hooks) {
    setenv("SHELL", "/bin/sh", 1);
    shadowhook_libc_envvar(hooks);
    shadowhook_envpolicy(hooks);
}

static void shdw_coord_symlookup(SHDWHookSession* hooks) {
    shadowhook_dyld_symlookup(hooks);
    shadowhook_dyld_symaddrlookup(hooks);
}

static void shdw_coord_verify_symlookup(void) {
    shadowhook_dyld_symlookup_verify();
    shadowhook_dyld_symaddrlookup_verify();
}

static void shdw_coord_detector_integrity(SHDWHookSession* hooks) {
    [Shadow shdwEnterInternalRead];
    @try {
        shadowhook_objc_methodimpl_detector(hooks);
        shadowhook_ImportSlotProtection(hooks);
    } @finally {
        [Shadow shdwExitInternalRead];
    }
}

static void shdw_coord_filesystem_objc(SHDWHookSession* hooks) {
    shadowhook_NSFileManager(hooks);
    shadowhook_NSFileHandle(hooks);
    shadowhook_NSFileVersion(hooks);
    shadowhook_NSFileWrapper(hooks);
}

static void shdw_coord_foundation_objc(SHDWHookSession* hooks) {
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

static void shdw_plugin_policy_nop(SHDWHookSession* hooks) { (void)hooks; }

// Must stay in SHDWPluginRegistry() order (Hybrid: verified vs SHDWPluginOrder.inc).
#import <Shadow/SHDWPluginOrder.inc>
static const SHDWPluginInstaller kSHDWPluginInstallers[] = {
    { "dyld",                         shadowhook_dyld,                 shadowhook_dyld_verify },
    { "Hook_Filesystem@c",            shadowhook_libc,                 shadowhook_libc_verify },
    { "Hook_EnvVars@c",               shdw_coord_envvars_c,            shadowhook_libc_envvar_verify },
    { "Hook_EnvVars@objc",            shadowhook_NSProcessInfo,        NULL },
    { "Hook_DeviceCheck",             shadowhook_DeviceCheck,          NULL },
    { "Hook_MachBootstrap",           shadowhook_mach,                 shadowhook_mach_verify },
    { "Hook_IOKit",                   shadowhook_iokit,                shadowhook_iokit_verify },
    { "Hook_LowLevelC",               shadowhook_libc_lowlevel,        shadowhook_libc_lowlevel_verify },
    { "Hook_AntiDebugging",           shadowhook_libc_antidebugging,   shadowhook_libc_antidebugging_verify },
    { "Hook_CodeSigning",             shadowhook_security,             shadowhook_security_verify },
    { "objc",                         shadowhook_objc,                 NULL },
    { "objc@methodimpl",              shadowhook_objc_methodimpl,      NULL },
    { "Hook_Syscall",                 shadowhook_syscall,              shadowhook_syscall_verify },
    { "Hook_Memory",                  shadowhook_mem,                  shadowhook_mem_verify },
    { "Hook_Sandbox",                 shadowhook_sandbox,              shadowhook_sandbox_verify },
    { "classes",                      shadowhook_objc_hidetweakclasses, NULL },
    { "symlookup",                    shdw_coord_symlookup,            shdw_coord_verify_symlookup },
    { "Hook_DynamicLibrariesExtra",   shadowhook_dyld_extra,           shadowhook_dyld_extra_verify },
    { "detector-integrity",            shdw_coord_detector_integrity,   NULL },
    { "Hook_Filesystem@objc",         shdw_coord_filesystem_objc,      NULL },
    { "Hook_Foundation@objc",         shdw_coord_foundation_objc,      NULL },
    { "Hook_HideApps",                shadowhook_LSApplicationWorkspace, NULL },
    { "Hook_URLScheme",               shadowhook_UIApplication,        NULL },
    { "Hook_Foundation@uikit",        shadowhook_UIImage,              NULL },
    { "Hook_DeviceSecurityKit",       shadowhook_DeviceSecurityKit,    NULL },
    // Policy plugins — no hook install, evaluated via RestrictionEngine
    { "Policy_Path",                  shdw_plugin_policy_nop,          NULL },
    { "Policy_Environment",           shdw_plugin_policy_nop,          NULL },
    { "Policy_Process",               shdw_plugin_policy_nop,          NULL },
    { "Policy_PseudoSandbox",         shdw_plugin_policy_nop,          NULL },
};
static const char* const kSHDWPluginInstallerOrderCheck[] __attribute__((unused)) = { SHDW_PLUGIN_ORDER };
_Static_assert(sizeof(kSHDWPluginInstallers)/sizeof(kSHDWPluginInstallers[0]) == sizeof(kSHDWPluginInstallerOrderCheck)/sizeof(kSHDWPluginInstallerOrderCheck[0]), "installer table drift vs SHDWPluginOrder.inc");
_Static_assert(sizeof(kSHDWPluginInstallers)/sizeof(kSHDWPluginInstallers[0]) == SHDW_PLUGIN_COUNT, "installer count != SHDW_PLUGIN_COUNT");

static void shdw_coordinator_ctor(NSDictionary<NSString*, id>* prefs) {
    shdw_coordinator_instance =
        [[SHDWHookCoordinator alloc] initWithInstallerTable:kSHDWPluginInstallers
                                                      count:sizeof(kSHDWPluginInstallers) / sizeof(kSHDWPluginInstallers[0])
                                                      prefs:prefs];

    if(!shdw_coordinator_instance) {
        NSLog(@"[Shadow][coordinator] init failed — continuing unhooked");
        return;
    }

    // Install synchronously: Shadow must be active before the app's main()
    // runs (the stub loader's whole point). The installers call into
    // ElleKit's substitutor, whose JIT-less exception-based hooking path
    // (brk #1) needs the exception handler up before any brk-patched hook
    // can fire. Pre-initialize it here so those hooks are handled instead of
    // trapping (observed: EXC_BREAKPOINT SIGTRAP during the dyld unit's
    // install when isPathRestricted re-enters a brk-patched function).
    void* ekLaunch = dlsym(RTLD_DEFAULT, "EKLaunchExceptionHandler");
    if(ekLaunch) {
        ((mach_port_t (*)(void))ekLaunch)();
    }

    [shdw_coordinator_instance installEvent:SHDWEventCtor];

    // Watcher replay runs after the install (it depends on the coordinator's
    // backends being resolved).
    _shdw_watcher_enabled = shdw_coordinator_instance
        && (shdw_coordinator_instance.backends.capabilities & SHDWCapMessage)
        && ([prefs[@"Hook_URLScheme"] boolValue] || [prefs[@"Hook_Foundation"] boolValue]);

    if(_shdw_watcher_enabled) {
        uint32_t count = _dyld_image_count();

        for(uint32_t i = 0; i < count; i++) {
            shdw_early_image_add(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
        }
    }

    NSLog(@"completed hooks");
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

        // Adapter support defaults on, but only an exact SDK fingerprint may
        // activate its library-specific behavior. Resolve before constructing
        // the hook plan because the iOSSecuritySuite profile narrows two
        // otherwise-wide groups and freeRASP enables raw-syscall coverage.
        prefs = shadowhook_DetectorAdapters_resolvePreferences(prefs);
        BOOL hasActiveDetectorAdapter = NO;
        for(NSString* key in @[ SHDWDetectorPatchDTTID, SHDWDetectorPatchSafeDeviceID,
                                SHDWDetectorPatchJailMonkeyID, SHDWDetectorPatchIOSSecuritySuiteID,
                                SHDWDetectorPatchFreeRASPID ]) {
            hasActiveDetectorAdapter |= [prefs[key] boolValue];
        }

        // IOSSecuritySuite exits during the full filesystem installer on
        // iOS 15. Its explicit adapter replaces that wide group with the seven
        // path-query hooks the SDK actually exercises (installed by the
        // DeviceCheck unit below).
        BOOL adaptIOSSecuritySuite = [prefs[SHDWDetectorPatchIOSSecuritySuiteID] boolValue] &&
            [prefs[SHDWHookIDDeviceCheck] boolValue] &&
            [prefs[SHDWHookIDFilesystem] boolValue];
        if(adaptIOSSecuritySuite || [prefs[SHDWDetectorPatchFreeRASPID] boolValue]) {
            NSMutableDictionary* effectivePrefs = [prefs mutableCopy];
            if(adaptIOSSecuritySuite) {
                effectivePrefs[SHDWHookIDFilesystem] = @NO;
                effectivePrefs[SHDWHookIDURLScheme] = @NO;
            }
            shadowhook_FreeRASP_preparePreferences(effectivePrefs);
            prefs = [effectivePrefs copy];
        }

        shdw_memory_hiding_enabled = [prefs[@"MemoryLevelHiding"] boolValue];

        [Shadow sharedInstance];
        shdw_own_ranges_refresh();
        shdw_pseudo_init(prefs);
        shadowhook_DeviceCheck_configure(prefs);

        NSLog(@"starting hooks");
        [Shadow shdwEnterInternalRead];
        @try {
            shdw_coordinator_ctor(prefs);

            // Swift source builds and Talsec binaries have no stable direct
            // hook ABI. Explicit adapters are known before detector code can
            // run, so install their Tier-2 coverage synchronously. Runtime
            // discoveries still use the deferred escalation path.
            if(hasActiveDetectorAdapter) {
                shdw_detector_present = YES;
                shdw_detector_write_policy_set_enabled(YES);
                [shdw_coordinator_instance prearmDetector];
            }
        } @finally {
            [Shadow shdwExitInternalRead];
        }
    } @catch (NSException* e) {
        NSLog(@"[Shadow] constructor failed: %@ — continuing unhooked", e);
        return;
    }

    NSLog(@"ctor returned (install deferred)");
}
