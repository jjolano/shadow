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

    [SHDWHookCoordinator shdw_requestPendingTargetDrain];

    if(!__atomic_load_n(&_shdw_watcher_enabled, __ATOMIC_ACQUIRE) ||
       __atomic_load_n(&_shdw_uikit_installed, __ATOMIC_ACQUIRE)) {
        return;
    }

    @autoreleasepool {
        const char* path = dyld_image_path_containing_address(mh);

        if(!path || !path[0]) {
            return;
        }

        NSString* image = [[NSString stringWithUTF8String:path] lowercaseString];

        if([image containsString:@"uikit.framework"] &&
           !__atomic_exchange_n(&_shdw_uikit_installed, YES, __ATOMIC_ACQ_REL)) {
            [shdw_coordinator_instance enqueueEvent:SHDWEventUIKitLoaded];
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
    { "Universal_Dyld",                       shdw_universal_dyld },
    { "Universal_Filesystem_C",               shdw_universal_filesystem_c },
    { "Universal_EnvVars_C",                  shdw_coord_envvars_c },
    { "Universal_EnvVars_ObjC",               shdw_universal_nsprocessinfo },
    { "Adapter_DeviceCheck",                   shdw_adapter_devicecheck },
    { "Adapter_FreeRASP",                      shdw_adapter_freerasp },
    { "Universal_MachBootstrap",              shdw_universal_mach_bootstrap },
    { "Universal_IOKit",                      shdw_universal_iokit },
    { "Universal_LowLevelC",                  shdw_universal_low_level_c },
    { "Universal_AntiDebugging",              shdw_universal_antidebugging },
    { "Universal_CodeSigning",                shdw_universal_codesigning },
    { "Universal_ObjC",                       shdw_universal_objc },
    { "Universal_ObjC_MethodImplementation",  shdw_universal_objc_methodimpl },
    { "Universal_Syscall",                    shdw_universal_syscall },
    { "Universal_Memory",                     shdw_universal_memory },
    { "Universal_Sandbox",                    shdw_universal_sandbox },
    { "Universal_HideClasses",                shdw_universal_hide_classes },
    { "Universal_SymbolLookup",               shdw_coord_symlookup },
    { "Universal_DynamicLibrariesExtra",      shdw_universal_dynamic_libraries_extra },
    { "Universal_DetectorIntegrity",          shdw_coord_detector_integrity },
    { "Universal_Filesystem_ObjC",            shdw_coord_filesystem_objc },
    { "Universal_Foundation_ObjC",            shdw_coord_foundation_objc },
    { "Universal_HideApps",                   shdw_universal_hide_apps },
    { "Universal_URLScheme",                  shdw_universal_url_scheme },
    { "Universal_Foundation_UIKit",           shdw_universal_foundation_uikit },
    { "Universal_PasscodeStatus",             shdw_universal_passcode_status },
    { "Adapter_DeviceSecurityKit",             shdw_adapter_devicesecuritykit },
    { "Adapter_IOSSecuritySuite",              shdw_adapter_iossecuritysuite },
    { "Adapter_BATJailbreakGuard",             shdw_adapter_batjailbreakguard },
    // Policy plugins — no hook install, evaluated via RestrictionEngine
    { "Policy_Path",                  shdw_plugin_policy_nop },
    { "Policy_Environment",           shdw_plugin_policy_nop },
    { "Policy_Process",               shdw_plugin_policy_nop },
    { "Policy_PseudoSandbox",         shdw_plugin_policy_nop },
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
        NSLog(@"[Shadow][coordinator] init failed — continuing");
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
    BOOL watcherEnabled = shdw_coordinator_instance
        && (shdw_coordinator_instance.backends.capabilities & SHDWCapMessage)
        && ([prefs[SHDWUniversalURLSchemeID] boolValue] || [prefs[SHDWUniversalFoundationID] boolValue]);
    __atomic_store_n(&_shdw_watcher_enabled, watcherEnabled, __ATOMIC_RELEASE);

    if(watcherEnabled) {
        uint32_t count = _dyld_image_count();

        for(uint32_t i = 0; i < count; i++) {
            shdw_early_image_add(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
        }
        if(__atomic_load_n(&_shdw_uikit_installed, __ATOMIC_ACQUIRE)) {
            [shdw_coordinator_instance installEvent:SHDWEventUIKitLoaded];
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

        // Capture authorization independently of current target readiness.
        shdw_adapter_devicecheck_configure(prefs);
        prefs = shdw_adapter_resolve_preferences(prefs);
        BOOL hasActiveDetectorAdapter = NO;
        for(NSString* key in @[ SHDWAdapterDTTJailbreakDetectionID, SHDWAdapterSafeDeviceID,
                                SHDWAdapterJailMonkeyID ]) {
            hasActiveDetectorAdapter |= [prefs[key] boolValue];
        }
        // Behavioral prearm for image/class-linked detectors whose adapters
        // are always-on (FreeRASP/Talsec, DeviceSecurityKit, IOSSecuritySuite,
        // BAT): their presence at ctor means detector code will run, so arm
        // Tier-2 now. Harness baseline unaffected: the harness links none of
        // these, and SDKFallback deferral is planner-gated, not prearm-gated.
        hasActiveDetectorAdapter |= shdw_adapter_has_known_detector();

        // The adapter's raw-syscall coverage is additive to the universal
        // groups and follows its own switch.
        {
            NSMutableDictionary* effectivePrefs = [prefs mutableCopy];
            if([effectivePrefs[SHDWAdapterFreeRASPID] boolValue]) {
                shdw_adapter_freerasp_prepare_preferences(effectivePrefs);
            }
            if([bundleIdentifier isEqualToString:@"me.jjolano.shadow.harness"]) {
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
            // Embedded detectors (harness links Talsec/DeviceSecurityKit/IOSSB
            // frameworks directly) count as an active detector presence, same
            // as the old isolated runners' linked images did.
            BOOL harnessPrearmed = [bundleIdentifier isEqualToString:@"me.jjolano.shadow.harness"] &&
                ![prefs[SHDWUniversalHarnessBaselineID] boolValue];
            BOOL embeddedDetectors = [bundleIdentifier isEqualToString:@"me.jjolano.shadow.harness"];
            BOOL forcedPrearm = [bundleIdentifier hasPrefix:@"me.jjolano.shadow.test."] ||
                bundleIdentifier.length == 0;
            if(hasActiveDetectorAdapter || harnessPrearmed || embeddedDetectors || forcedPrearm) {
                shdw_detector_present = YES;
                shdw_detector_write_policy_set_enabled(YES);
                [shdw_coordinator_instance prearmDetector];
            }
        } @finally {
            [Shadow shdwExitInternalRead];
        }
    } @catch (NSException* e) {
        NSLog(@"[Shadow] constructor failed: %@ — continuing", e);
        return;
    }
}
