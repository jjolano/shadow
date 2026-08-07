#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import "../common.h"
#import "hooks/hooks.h"

#import <Shadow.h>
#import <Shadow/Settings.h>
#import <libSandy.h>
#import <HookKit.h>
#import <RootBridge.h>

#import "../vendor/apple/dyld_priv.h"   // dyld_image_path_containing_address

// Set when a known detection library is loaded (see %ctor); consumed by
// dyld.x (memory-hiding escalation) and by the hook-backend routing below.
BOOL shdw_detector_present = NO;

// ---------------------------------------------------------------------------
// Spawn-time image watcher (no-Filter loading: the tweak now loads at process
// spawn instead of at UIKit load). An add-image callback is registered before
// any hooking so that (a) app-linked detection libraries — which load after
// this ctor — still trigger the AR4 escalation, and (b) the UIKit-class hook
// groups (UIApplication, UIImage) install only once UIKit is actually loaded:
// %init on a class that doesn't exist yet can crash Substrate-based backends
// and silently kills the group on ElleKit.
// ---------------------------------------------------------------------------
#ifdef hookkit_h
static BOOL _shdw_watcher_enabled = NO;      // ctor passed all gates + prefs on
static BOOL _shdw_watcher_started = NO;      // single-shot replay guard
static BOOL _shdw_objc_backend = NO;         // ElleKit/Substrate/Substitute available
static BOOL _shdw_pref_urlscheme = NO;
static BOOL _shdw_pref_foundation = NO;
static BOOL _shdw_dyld_installed = NO;       // set when the ctor installed the group
static BOOL _shdw_symlookup_installed = NO;
static BOOL _shdw_dyldextra_installed = NO;
static BOOL _shdw_uikit_installed = NO;      // UIKit groups installed
static BOOL _shdw_escalation_installed = NO; // detector escalation handled
static HKSubstitutor* _shdw_watcher_main = nil;   // subMain
static HKSubstitutor* _shdw_watcher_cfunc = nil;  // subCFunc
static HKSubstitutor* _shdw_watcher_inline = nil; // subInline (inline escalation)

// shdw_early_image_add resolves the image header to its path via the PUBLIC
// dyld_image_path_containing_address (declared in vendor/apple/dyld_priv.h,
// present on every supported OS) — not the private dyld4
// _dyld_image_header_file_path, which doesn't exist on rooted iOS 12-14 and
// would risk a load failure there. Once the dyld groups install, this call
// routes through their hook: visible images (UIKit etc.) resolve to their
// real path, restricted images resolve to the executable path (masked) — a
// masked detector image can't be classified by name here, but the dyld
// groups are installed by then and the behavioral tripwires (dlopen/dlsym/
// dladdr probes) cover that escalation.
static void shdw_early_image_add(const struct mach_header* mh, intptr_t vmaddr_slide) {
    (void) vmaddr_slide;

    if(!_shdw_watcher_enabled) {
        return;  // daemon / non-app / prefs-off: nothing to defer or escalate
    }

    @autoreleasepool {
        const char* path = dyld_image_path_containing_address(mh);

        if(!path || !path[0]) {
            return;  // fail soft: no name to classify
        }

        NSString* image_lower = [[NSString stringWithUTF8String:path] lowercaseString];

        // UIKit is loaded: the classes now exist. Install the two UIKit-class
        // groups the ctor must not %init at spawn (class absent there).
        if(!_shdw_uikit_installed && [image_lower containsString:@"uikit.framework"]) {
            if(_shdw_objc_backend && (_shdw_pref_urlscheme || _shdw_pref_foundation)) {
                NSLog(@"+ uikit classes (installed at UIKit load)");

                if(_shdw_pref_urlscheme) {
                    shadowhook_UIApplication(_shdw_watcher_main);
                }

                if(_shdw_pref_foundation) {
                    shadowhook_UIImage(_shdw_watcher_main);
                }

                [_shdw_watcher_main executeHooks];
            }

            _shdw_uikit_installed = YES;
        }

        // Detector loaded after our ctor (app-linked or dlopen'd): escalate.
        // shdw_detector_detected installs the gated groups the ctor skipped
        // (idempotent — its guard covers the prefs-installed subset).
        if([image_lower containsString:@"iossecuritysuite"]
        || [image_lower containsString:@"freerasp"] || [image_lower containsString:@"talsec"]) {
            shdw_detector_detected(path);
        }
    }
}
#endif

// Detector escalation, shared by the image watcher and the behavioral
// tripwires in the hook files (JB-indicator path/symbol/dylib probes by
// non-tweak callers). Sets the flag, then installs whatever detector-gated
// groups the ctor didn't (the ctor only skipped them when the flag was NO at
// spawn — with the flag now YES, a second pass would double-hook, hence the
// per-group guards). Re-entrancy: the escalation guard is marked before any
// install, so a trip firing from inside a hook being installed no-ops.
void shdw_detector_detected(const char* reason) {
    #ifdef hookkit_h
    if(_shdw_escalation_installed) {
        return;
    }

    _shdw_escalation_installed = YES;

    NSLog(@"[Shadow] detector probe: %s", reason ?: "unknown");

    shdw_detector_present = YES;

    if(!_shdw_dyld_installed) {
        shadowhook_dyld(_shdw_watcher_cfunc);
    }

    if(!_shdw_symlookup_installed) {
        HKSubstitutor* sub = _shdw_watcher_inline ?: _shdw_watcher_main;
        shadowhook_dyld_symlookup(sub);
        shadowhook_dyld_symaddrlookup(sub);
    }

    if(!_shdw_dyldextra_installed) {
        shadowhook_dyld_extra(_shdw_watcher_inline ?: _shdw_watcher_main);
    }

    [_shdw_watcher_cfunc executeHooks];
    [_shdw_watcher_main executeHooks];
    #else
    (void) reason;
    #endif
}

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

    // Watch for images that load after this ctor (no-Filter loading means the
    // ctor runs at spawn, before app-linked detectors and UIKit exist): late
    // detector arrivals escalate the dyld surface, and the UIKit-class hook
    // groups install once UIKit is actually loaded. Registered before any
    // hooking, so the callback stays on dyld's real list. dyld replays the
    // already-loaded images at registration — while the watcher is still
    // disabled (prefs not yet read), so every one of them is discarded; the
    // ctor re-delivers them once the watcher is enabled (replay below the
    // group installs).
    #ifdef hookkit_h
    _dyld_register_func_for_add_image(shdw_early_image_add);
    #endif

    // Determine the application we're injected into.
    NSString* bundleIdentifier = [Shadow getBundleIdentifier];

    // Injected into SpringBoard: nothing to do — the hook_springboard group
    // was removed in v5, and vnode hiding is per-app only (SB holds no lease;
    // the daemon owns recovery).
    if([bundleIdentifier isEqualToString:@"com.apple.springboard"]) {
        return;
    }

    NSString* executablePath = [Shadow getExecutablePath];
    NSString* bundleType = [[executablePath stringByDeletingLastPathComponent] pathExtension];

    // Only load Shadow for applications in /var.
    if(![bundleType isEqualToString:@"app"]) {
        return;
    }

    // TEST-ONLY allowlist: dyldprobe (the W5/W2 verification probe) installs
    // to /Applications, which the check below would otherwise exclude — let
    // Shadow load into it so hiding can be verified on-device. Exact
    // bundle-id match only; the com.apple / jailbreak-tool denylists below
    // still apply.
    BOOL isDyldProbe = [bundleIdentifier isEqualToString:@"me.jjolano.dyldprobe"];

    if(!isDyldProbe && ([executablePath hasPrefix:@"/Applications"]
    || [executablePath hasPrefix:@"/System"]
    || [executablePath hasPrefix:@"/private/preboot"]
    || [executablePath hasPrefix:@"/var/jb"])) {
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

    // Vnode-layer hiding: acquire the daemon lease now — immediately after
    // prefs/rulesets are read, before any hook group installs, so ctor-time
    // probes see the hide from the start. The daemon derives the paths from
    // its own allowlist; the client sends no paths and touches no kernel
    // state. Pure IPC, sub-millisecond; whether hiding is enabled is
    // enforced daemon-side.
    shadowhook_vnode(NULL);

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

    // subMain: ALWAYS the default substitutor. The HK_Library pref may only
    // configure the C-function substitutors (subCFunc/subSymLookup below) —
    // subMain backs every ObjC-method hook group, and fishhook cannot swizzle
    // ObjC methods, so applying the pref here (as before) silently broke
    // those groups whenever the pref picked fishhook. Never setTypes: on
    // subMain.
    HKSubstitutor* subMain = [HKSubstitutor defaultSubstitutor];

    // ObjC groups need a method-swizzling backend. With no ElleKit /
    // Substrate / Substitute available (e.g. pref=fishhook on a fishhook-only
    // device) subMain is fishhook-only and those groups would fail at hook
    // time anyway — log once and skip them gracefully, never crash.
    hookkit_lib_t available_types = [HKSubstitutor getAvailableSubstitutorTypes];
    BOOL objcBackendAvailable = (available_types & (HK_LIB_ELLEKIT | HK_LIB_SUBSTRATE | HK_LIB_SUBSTITUTE)) != 0;

    if(!objcBackendAvailable) {
        NSLog(@"[Shadow] no ObjC-capable hooking library available (only fishhook); skipping ObjC-method hook groups");
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

    // C-function groups: the HK_Library pref picks the backend here —
    // fishhook by default (clean prologues), ElleKit when explicitly
    // selected (stale substrate/substitute prefs fall back to fishhook).
    // Escalation: with a detection library present, stealth beats the pref —
    // C groups stay on fishhook even if the pref selected ElleKit.
    HKSubstitutor* subCFunc = subFish ? subFish : subMain;

    if(!shdw_detector_present && (hooklibs & HK_LIB_ELLEKIT)) {
        subCFunc = subInline ? subInline : subMain;
    }

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

    // Stash state for the spawn-time watcher (shdw_early_image_add): it runs
    // on dyld's loader thread for images loaded after this ctor and needs the
    // substitutors/prefs without touching ctor locals.
    #ifdef hookkit_h
    _shdw_objc_backend = objcBackendAvailable;
    _shdw_pref_urlscheme = [prefs_load[@"Hook_URLScheme"] boolValue];
    _shdw_pref_foundation = [prefs_load[@"Hook_Foundation"] boolValue];

    // The watcher only runs when a hook group needs it: the UIKit-class
    // groups (urlscheme/foundation prefs + an ObjC backend) or late-detector
    // escalation (no detector at spawn — the ctor handles spawn-time
    // detectors itself and marks the escalation installed below, so a watcher
    // with nothing left to do stays disabled).
    _shdw_watcher_enabled = !shdw_detector_present
        || (objcBackendAvailable && (_shdw_pref_urlscheme || _shdw_pref_foundation));
    _shdw_watcher_main = subMain;
    _shdw_watcher_cfunc = subCFunc;
    _shdw_watcher_inline = subInline;

    // Detector present at spawn: the ctor's detector-gated installs below run
    // (their conditions include shdw_detector_present); tell the watcher the
    // escalation is already handled so it never double-installs.
    if(shdw_detector_present) {
        _shdw_escalation_installed = YES;
    }
    #endif

    // AR4 escalation: when a detection library is present these dyld hooks
    // install regardless of the corresponding prefs — a detector in the
    // process sees the jailbreak either way, so the prefs must not be able
    // to leave the dyld surface exposed.
    if([prefs_load[@"Hook_DynamicLibraries"] boolValue] || shdw_detector_present) {
        NSLog(@"+ dylib");
        
        shadowhook_dyld(subCFunc);

        #ifdef hookkit_h
        _shdw_dyld_installed = YES;
        #endif
    }

    if([prefs_load[@"Hook_Filesystem"] boolValue]) {
        NSLog(@"+ filesystem");

        shadowhook_libc(subCFunc);

        if(objcBackendAvailable) {
            shadowhook_NSFileManager(subMain);
            shadowhook_NSFileHandle(subMain);
            shadowhook_NSFileVersion(subMain);
            shadowhook_NSFileWrapper(subMain);
        }
    }

    if([prefs_load[@"Hook_URLScheme"] boolValue]) {
        // Installed by shdw_early_image_add once UIKit is loaded: the class
        // doesn't exist at spawn (no-Filter loading), where %init on it could
        // crash Substrate-based backends.
        NSLog(@"+ urlscheme");
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

        if(objcBackendAvailable) {
            shadowhook_NSArray(subMain);
            shadowhook_NSDictionary(subMain);
            shadowhook_NSBundle(subMain);
            shadowhook_NSString(subMain);
            shadowhook_NSURL(subMain);
            shadowhook_NSData(subMain);
            // UIImage needs UIKit loaded; installed by shdw_early_image_add
            // (see the Hook_URLScheme block above for why).
            shadowhook_NSThread(subMain);
        }
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

        if(objcBackendAvailable) {
            // libobjc C functions (objc_copyImageNames etc.) are exported symbols
            // fishhook could rebind, but the runtime calls some of them directly
            // in hot paths — keep them inline via subMain to be safe.
            shadowhook_objc(subMain);
        }
    }

    if([prefs_load[@"Hook_FakeMac"] boolValue]) {
        NSLog(@"+ m1");

        if(objcBackendAvailable) {
            shadowhook_NSProcessInfo_fakemac(subMain);
        }
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

        if(objcBackendAvailable) {
            shadowhook_LSApplicationWorkspace(subMain);
        }
    }

    if([prefs_load[@"Hook_Sandbox"] boolValue]) {
        NSLog(@"+ sandbox");

        shadowhook_sandbox(subCFunc);
    }

    if([prefs_load[@"Hook_TweakClasses"] boolValue]) {
        NSLog(@"+ classes");
        
        if(objcBackendAvailable) {
            // Same reasoning as shadowhook_objc above: C-function hooks in the
            // runtime path stay on subMain.
            shadowhook_objc_hidetweakclasses(subMain);
        }
    }

    if([prefs_load[@"Hook_SymLookup"] boolValue] || shdw_detector_present) {
        NSLog(@"+ dlsym");

        // dlsym/dladdr: fishhook keeps prologues clean; escalates to inline
        // (denyFishHook-immune) when a detection library is present.
        shadowhook_dyld_symlookup(subSymLookup);
        shadowhook_dyld_symaddrlookup(subSymLookup);

        #ifdef hookkit_h
        _shdw_symlookup_installed = YES;
        #endif
    }

    if([prefs_load[@"Hook_DynamicLibrariesExtra"] boolValue] || shdw_detector_present) {
        NSLog(@"+ dylibex");

        // dlopen_internal is a private libdyld symbol fishhook can't rebind —
        // inline only, always.
        shadowhook_dyld_extra(subDyldExtra);

        #ifdef hookkit_h
        _shdw_dyldextra_installed = YES;
        #endif
    }

    #ifdef hookkit_h
    // Replay the already-loaded images into the watcher. The add-image
    // callback was registered at the top of this ctor — before any hooking,
    // so it sits on dyld's real list — and dyld's registration-time replay
    // ran while _shdw_watcher_enabled was still NO, discarding every
    // already-loaded image (UIKit among them). Deliver them now that the
    // flag is on. No image is delivered twice: the registration-time replay
    // ran while the flag was NO, dyld never re-replays, and the per-group
    // guards inside the callback (_shdw_uikit_installed,
    // _shdw_escalation_installed) make any duplicate delivery a no-op;
    // _shdw_watcher_started keeps this single-shot regardless.
    if(_shdw_watcher_enabled && !_shdw_watcher_started) {
        _shdw_watcher_started = YES;

        uint32_t replay_count = _dyld_image_count();

        for(uint32_t i = 0; i < replay_count; i++) {
            shdw_early_image_add(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
        }
    }

    [subFish executeHooks];
    [subFish setBatching:NO];
    [subInline executeHooks];
    [subInline setBatching:NO];
    HKExecuteBatch();
    HKDisableBatching();
    #endif

    NSLog(@"completed hooks");
}

%dtor {
    // Best-effort lease release at process teardown. The daemon also watches
    // the service-port send right, so this is courtesy only.
    shadowhook_vnode_release();
}
