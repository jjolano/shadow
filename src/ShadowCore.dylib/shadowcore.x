#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import "../common.h"
#import <Shadow/JBPath.h>
#import "hooks/hooks.h"
#import "hooks/UniversalHooks.h"
#import "hooks/AdapterHooks.h"
#import "policy/PathPolicy.h"

#import <Shadow.h>
#import <Shadow/Settings.h>
#import <libSandy.h>

#include <time.h>
#include <dlfcn.h>
#include <mach/mach.h>

#import "HookCoordinator.h"
#import "../../vendor/apple/dyld_priv.h"

// Set by an exact detector-adapter match or behavioral tripwires.
BOOL shdw_detector_present = NO;

// Emergency kill-switch for the dyld_all_image_infos memory-hiding patch.
BOOL shdw_memory_hiding_enabled = YES;

// User opt-in (global or per-app, resolved in getPreferencesForIdentifier:):
// when YES, adapters may run disable-style neutralizers that force a detector's
// check result rather than only shaping a stock-looking environment.
BOOL shdw_detector_aggressive = NO;

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
    shdw_universal_envvars_c(hooks);
    shdw_universal_envpolicy(hooks);
}

static void shdw_coord_symlookup(SHDWHookSession* hooks) {
    shdw_universal_symlookup(hooks);
    shdw_universal_symaddrlookup(hooks);
}

static void shdw_coord_verify_symlookup(void) {
    shdw_universal_symlookup_verify();
    shdw_universal_symaddrlookup_verify();
}

static void shdw_coord_detector_integrity(SHDWHookSession* hooks) {
    [Shadow shdwEnterInternalRead];
    @try {
        shdw_universal_objc_methodimpl_detector(hooks);
        shdw_universal_import_slot_protection(hooks);
    } @finally {
        [Shadow shdwExitInternalRead];
    }
}

static void shdw_coord_filesystem_objc(SHDWHookSession* hooks) {
    shdw_universal_filesystem_objc(hooks);
    shdw_universal_nsfilehandle(hooks);
    shdw_universal_nsfileversion(hooks);
    shdw_universal_nsfilewrapper(hooks);
}

static void shdw_coord_foundation_objc(SHDWHookSession* hooks) {
    shdw_universal_nsarray(hooks);
    shdw_universal_nsdictionary(hooks);
    shdw_universal_nsbundle(hooks);
    shdw_universal_nsstring(hooks);
    shdw_universal_nsurl(hooks);
    shdw_universal_nsdata(hooks);
    shdw_universal_nsthread(hooks);
    shdw_universal_user_defaults(hooks);
    shdw_universal_nstask(hooks);
}

static void shdw_plugin_policy_nop(SHDWHookSession* hooks) { (void)hooks; }

// Must stay in SHDWPluginRegistry() order (Hybrid: verified vs SHDWPluginOrder.inc).
#import <Shadow/SHDWPluginOrder.inc>
static const SHDWPluginInstaller kSHDWPluginInstallers[] = {
    { "Universal_Dyld",                       shdw_universal_dyld,                     shdw_universal_dyld_verify },
    { "Universal_Filesystem_C",               shdw_universal_filesystem_c,             shdw_universal_filesystem_c_verify },
    { "Universal_EnvVars_C",                  shdw_coord_envvars_c,                    shdw_universal_envvars_c_verify },
    { "Universal_EnvVars_ObjC",               shdw_universal_nsprocessinfo,            NULL },
    { "Adapter_DeviceCheck",                   shdw_adapter_devicecheck,                NULL },
    { "Adapter_FreeRASP",                      shdw_adapter_freerasp,                   NULL },
    { "Universal_MachBootstrap",              shdw_universal_mach_bootstrap,           shdw_universal_mach_bootstrap_verify },
    { "Universal_IOKit",                      shdw_universal_iokit,                    shdw_universal_iokit_verify },
    { "Universal_LowLevelC",                  shdw_universal_low_level_c,              shdw_universal_low_level_c_verify },
    { "Universal_AntiDebugging",              shdw_universal_antidebugging,            shdw_universal_antidebugging_verify },
    { "Universal_CodeSigning",                shdw_universal_codesigning,              shdw_universal_codesigning_verify },
    { "Universal_ObjC",                       shdw_universal_objc,                     NULL },
    { "Universal_ObjC_MethodImplementation",  shdw_universal_objc_methodimpl,          NULL },
    { "Universal_Syscall",                    shdw_universal_syscall,                  shdw_universal_syscall_verify },
    { "Universal_Memory",                     shdw_universal_memory,                   shdw_universal_memory_verify },
    { "Universal_Sandbox",                    shdw_universal_sandbox,                  shdw_universal_sandbox_verify },
    { "Universal_HideClasses",                shdw_universal_hide_classes,             NULL },
    { "Universal_SymbolLookup",               shdw_coord_symlookup,                    shdw_coord_verify_symlookup },
    { "Universal_DynamicLibrariesExtra",      shdw_universal_dynamic_libraries_extra,  shdw_universal_dynamic_libraries_extra_verify },
    { "Universal_DetectorIntegrity",          shdw_coord_detector_integrity,           NULL },
    { "Universal_Filesystem_ObjC",            shdw_coord_filesystem_objc,              NULL },
    { "Universal_Foundation_ObjC",            shdw_coord_foundation_objc,              NULL },
    { "Universal_HideApps",                   shdw_universal_hide_apps,                NULL },
    { "Universal_URLScheme",                  shdw_universal_url_scheme,               NULL },
    { "Universal_Foundation_UIKit",           shdw_universal_foundation_uikit,         NULL },
    { "Adapter_DeviceSecurityKit",             shdw_adapter_devicesecuritykit,          NULL },
    { "Adapter_IOSSecuritySuite",              shdw_adapter_iossecuritysuite,           NULL },
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
        && ([prefs[SHDWUniversalURLSchemeID] boolValue] || [prefs[SHDWUniversalFoundationID] boolValue]);

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

        // Adapter switches are enabled by default. Exact fingerprints only
        // narrow the descriptor-backed detector rows before installation.
        prefs = shdw_adapter_resolve_preferences(prefs);
        BOOL hasActiveDetectorAdapter = NO;
        for(NSString* key in @[ SHDWAdapterDTTJailbreakDetectionID, SHDWAdapterSafeDeviceID,
                                SHDWAdapterJailMonkeyID ]) {
            hasActiveDetectorAdapter |= [prefs[key] boolValue];
        }

        // The adapter's raw-syscall coverage is additive to the universal
        // groups and follows its own switch.
        {
            NSMutableDictionary* effectivePrefs = [prefs mutableCopy];
            if([effectivePrefs[SHDWAdapterFreeRASPID] boolValue]) {
                shdw_adapter_freerasp_prepare_preferences(effectivePrefs);
            }
            if([bundleIdentifier isEqualToString:@"me.jjolano.shadow.harness"] &&
               effectivePrefs[SHDWUniversalHarnessBaselineID] == nil) {
                effectivePrefs[SHDWUniversalHarnessBaselineID] = @YES;
            }
            prefs = [effectivePrefs copy];
        }

        shdw_path_rewrite_configure([prefs[SHDWUniversalPathRewriteID] boolValue]);
        shdw_memory_hiding_enabled = [prefs[SHDWUniversalMemoryLevelHidingID] boolValue];
        shdw_detector_aggressive = [prefs[SHDWDetectorAggressiveID] boolValue];

        Shadow* shadow = [Shadow sharedInstance];
        [shadow shdwConfigurePseudoSandboxMode:[prefs[SHDWUniversalPseudoSandboxModeID] integerValue]];
        shdw_own_ranges_refresh();
        shdw_adapter_devicecheck_configure(prefs);
        shdw_universal_register_features();

        NSLog(@"starting hooks");
        [Shadow shdwEnterInternalRead];
        @try {
            shdw_coordinator_ctor(prefs);

            // Hide any suspicious LC_LOAD_DYLIB names baked into the main
            // executable at link time (e.g. an app linked against
            // Shadow.framework) from a raw Mach-O memory walk.
            shdw_hide_main_image_loadcmd_names();

            // Swift source builds and Talsec binaries have no stable direct
            // hook ABI. Prearm framework-independent Tier-2 coverage before
            // detector code can run. Production adapter switches install at
            // construction; the harness keeps its deferred fallback event.
            // Harness sets this false only for its explicit prearmed mode.
            // Prearm the detector-only units before its first real detector
            // runs; normal Harness launches retain the universal baseline.
            BOOL harnessPrearmed = [bundleIdentifier isEqualToString:@"me.jjolano.shadow.harness"] &&
                ![prefs[SHDWUniversalHarnessBaselineID] boolValue];
            BOOL forcedPrearm = [bundleIdentifier hasPrefix:@"me.jjolano.shadow.test."] ||
                bundleIdentifier.length == 0;
            if(hasActiveDetectorAdapter || harnessPrearmed || forcedPrearm) {
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
