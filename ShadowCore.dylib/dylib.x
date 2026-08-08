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

// Set only by shdw_detector_detected, which the behavioral tripwires in the
// hook files (JB-indicator path/symbol/dylib probes by non-tweak callers)
// invoke — never by image-name matching. Consumed by the vnode hiding gate
// (vnode.x) and by the hook-backend routing below.
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
static BOOL _shdw_pref_filesystem = NO;
static BOOL _shdw_pref_fakemac = NO;
static BOOL _shdw_pref_hideapps = NO;
static BOOL _shdw_dyld_installed = NO;       // set when the ctor installed the group
static BOOL _shdw_symlookup_installed = NO;
static BOOL _shdw_dyldextra_installed = NO;
static BOOL _shdw_uikit_installed = NO;      // UIKit groups installed
static BOOL _shdw_escalation_installed = NO; // detector escalation handled
static BOOL _shdw_tier2_installed = NO;      // ObjC groups installed on first probe
static BOOL _shdw_objc_installed = NO;       // C0-4: shadowhook_objc group installed
static BOOL _shdw_tweakclasses_installed = NO; // C0-4: hidetweakclasses group installed
static HKSubstitutor* _shdw_watcher_main = nil;   // subMain
static HKSubstitutor* _shdw_watcher_cfunc = nil;  // subCFunc
static HKSubstitutor* _shdw_watcher_inline = nil; // subInline (inline escalation)

static void shdw_install_tier2(void);  // defined with shdw_detector_detected

// shdw_early_image_add resolves the image header to its path via the PUBLIC
// dyld_image_path_containing_address (declared in vendor/apple/dyld_priv.h,
// present on every supported OS) — not the private dyld4
// _dyld_image_header_file_path, which doesn't exist on rooted iOS 12-14 and
// would risk a load failure there. The path is used only to detect UIKit
// load; no image is ever classified by name for escalation (identity
// concealment is name-independent — detection attempts escalate only via the
// behavioral tripwires in the hook files).
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

        // No detector classification by image name: the identity groups
        // install for every enabled app at the ctor (see below), and a late
        // detection attempt escalates via the behavioral tripwires (path /
        // symbol probes) in the hook files, which call
        // shdw_detector_detected directly.
    }
}
#endif

// Detector escalation, invoked by the behavioral tripwires in the hook files
// (JB-indicator path/symbol/dylib probes by non-tweak callers) — never by
// image-name matching. Sets the flag, then arms what the ctor left
// detector-gated: the vnode client, the dyldextra group (inline only) and
// the tier-2 ObjC swizzle groups. The identity groups the ctor installs
// unconditionally (dyld, objc, hidetweakclasses, symlookup) are not touched
// here. Re-entrancy: the escalation guard is marked before any install, so a
// trip firing from inside a hook being installed no-ops.
void shdw_detector_detected(const char* reason) {
    #ifdef hookkit_h
    if(_shdw_escalation_installed) {
        return;
    }

    _shdw_escalation_installed = YES;

    NSLog(@"[Shadow] detector probe: %s", reason ?: "unknown");

    shdw_detector_present = YES;

    // Detector escalation also arms the vnode client: its gate re-evaluates
    // per call, so a detector that appeared after the ctor's gate check
    // still triggers the (once-per-process) acquire.
    shadowhook_vnode(NULL);

    // dyldextra (dlopen_internal) stays detector-evidence-gated — the ctor
    // only installs it when the pref is on. fishhook cannot rebind the
    // private libdyld symbol, so inline only: on a fishhook-only device
    // _shdw_watcher_inline is nil — skip, fail-soft, never fall back to a
    // non-inline substitutor.
    if(!_shdw_dyldextra_installed) {
        if(!_shdw_watcher_inline) {
            NSLog(@"[Shadow] dyldextra skipped: no inline backend (dlopen_internal needs one)");
        } else {
            shadowhook_dyld_extra(_shdw_watcher_inline);
        }
    }

    // C0-4: the ObjC runtime / tweak-class groups are installed by the ctor
    // for every enabled app (identity concealment), so on detector evidence
    // they are already in — the guards below keep this idempotent.
    if(_shdw_objc_backend && _shdw_watcher_main) {
        if(!_shdw_objc_installed) {
            NSLog(@"+ objc (installed on detector evidence)");
            shadowhook_objc(_shdw_watcher_main);
            _shdw_objc_installed = YES;
        }

        if(!_shdw_tweakclasses_installed) {
            NSLog(@"+ classes (installed on detector evidence)");
            shadowhook_objc_hidetweakclasses(_shdw_watcher_main);
            _shdw_tweakclasses_installed = YES;
        }
    }

    // Tier-2: the ObjC-method swizzle groups install on detector evidence,
    // not at spawn — clean apps never pay their per-call cost or crash
    // surface. The probe that triggered this was already answered by the
    // tier-1 C groups (a detector's first check is a path probe), so hiding
    // isn't delayed for the initiating check.
    shdw_install_tier2();

    [_shdw_watcher_cfunc executeHooks];
    [_shdw_watcher_main executeHooks];
    #else
    (void) reason;
    #endif
}

// Tier-2 lazy activation (see shdw_detector_detected). Prefs still gate which
// groups install; only the timing moves. UIKit classes (UIApplication,
// UIImage) stay gated on UIKit load via the watcher, not here.
static void shdw_install_tier2(void) {
    #ifdef hookkit_h
    if(_shdw_tier2_installed || !_shdw_objc_backend) {
        return;
    }

    _shdw_tier2_installed = YES;

    if(_shdw_pref_filesystem) {
        NSLog(@"+ filesystem (ObjC groups installed on probe)");

        shadowhook_NSFileManager(_shdw_watcher_main);
        shadowhook_NSFileHandle(_shdw_watcher_main);
        shadowhook_NSFileVersion(_shdw_watcher_main);
        shadowhook_NSFileWrapper(_shdw_watcher_main);
    }

    if(_shdw_pref_foundation) {
        NSLog(@"+ foundation (ObjC groups installed on probe)");

        shadowhook_NSArray(_shdw_watcher_main);
        shadowhook_NSDictionary(_shdw_watcher_main);
        shadowhook_NSBundle(_shdw_watcher_main);
        shadowhook_NSString(_shdw_watcher_main);
        shadowhook_NSURL(_shdw_watcher_main);
        shadowhook_NSData(_shdw_watcher_main);
        shadowhook_NSThread(_shdw_watcher_main);
    }

    if(_shdw_pref_fakemac) {
        shadowhook_NSProcessInfo_fakemac(_shdw_watcher_main);
    }

    if(_shdw_pref_hideapps) {
        shadowhook_LSApplicationWorkspace(_shdw_watcher_main);
    }

    [_shdw_watcher_main executeHooks];
    #else
    (void) 0;
    #endif
}

%ctor {
    // No detector classification by image name: identity concealment must not
    // depend on knowing a detector's name, so the identity groups below
    // install for every enabled app unconditionally, and detection attempts
    // escalate only through the behavioral tripwires (see
    // shdw_detector_detected).

    // Watch for images that load after this ctor (no-Filter loading means the
    // ctor runs at spawn, before UIKit exists): the UIKit-class hook groups
    // install once UIKit is actually loaded. Registered before any hooking,
    // so the callback stays on dyld's real list. dyld replays the
    // already-loaded images at registration — while the watcher is still
    // disabled (prefs not yet read), so every one of them is discarded; the
    // ctor re-delivers them once the watcher is enabled (replay below the
    // group installs).
    #ifdef hookkit_h
    _dyld_register_func_for_add_image(shdw_early_image_add);
    #endif

    // The stub (Shadow.dylib) already gated on the bundle identifier; the
    // payload is only dlopen'd for enabled apps, so re-derive it here for the
    // prefs lookup (the ctor's original gate block moved into the stub).
    NSString* bundleIdentifier = [NSBundle mainBundle].bundleIdentifier;

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

    // Build the caller-classification ranges unconditionally — before any
    // hook group installs — so isCallerExternal() is correct even when the
    // Dynamic Libraries group is disabled (dyld.x otherwise only refreshes
    // at its own install; with the group off the published set would stay
    // empty and caller-gated hooks would classify every caller as external,
    // bypassing the restrictions).
    shdw_own_ranges_refresh();

    // Vnode-layer hiding: acquire the daemon lease now — immediately after
    // prefs/rulesets are read, before any hook group installs, so ctor-time
    // probes see the hide from the start. The daemon derives the paths from
    // its own allowlist; the client sends no paths and touches no kernel
    // state. Pure IPC, sub-millisecond; the VnodeHiding pref gate
    // (client-side, detector escalation) is checked inside.
    shadowhook_vnode(NULL);

    // Initialize hooks.
    NSLog(@"starting hooks");

    // Fail-soft: an unexpected NSException from the hooking library during
    // install must not crash the app at spawn — log and continue unhooked
    // (the verify functions below surface what failed to install).
    @try {
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

    // subMain: ALWAYS the default substitutor, except on devices where no
    // runtime library is loaded (see below). The HK_Library pref may only
    // configure the C-function substitutors (subCFunc/subSymLookup below) —
    // subMain backs every ObjC-method hook group, and fishhook cannot swizzle
    // ObjC methods, so applying the pref here (as before) silently broke
    // those groups whenever the pref picked fishhook. Never setTypes: on
    // subMain.

    // ObjC groups need a method-swizzling backend. With no ElleKit /
    // Substrate / Substitute available (e.g. pref=fishhook on a fishhook-only
    // device) the default substitutor is fishhook-only and those groups would
    // fail at hook time anyway — log once and skip them gracefully, never
    // crash.
    hookkit_lib_t available_types = [HKSubstitutor getAvailableSubstitutorTypes];
    BOOL runtimeBackendAvailable = (available_types & (HK_LIB_ELLEKIT | HK_LIB_SUBSTRATE | HK_LIB_SUBSTITUTE)) != 0;

    // subMain: the default substitutor, EXCEPT on devices where no runtime
    // library is loaded — there the default lands on fishhook, which cannot
    // swizzle ObjC methods, so fall back to HookKit's own native backend
    // (arm64/arm64e, HK_LIB_NATIVE, also message-capable). The HK_Library pref
    // never configures subMain: fishhook cannot swizzle ObjC methods, so
    // applying the pref here silently broke every ObjC group.
    HKSubstitutor* subMain = runtimeBackendAvailable ? [HKSubstitutor defaultSubstitutor]
        : ((available_types & HK_LIB_NATIVE) ? [HKSubstitutor substitutorWithTypes:HK_LIB_NATIVE] : [HKSubstitutor defaultSubstitutor]);

    BOOL objcBackendAvailable = runtimeBackendAvailable || (available_types & HK_LIB_NATIVE);

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
    // dlopen_internal. Used for dlopen_internal always, and inline-first for
    // the dlsym/dladdr pair (see subSymLookup below).
    HKSubstitutor* subInline = ([HKSubstitutor getAvailableSubstitutorTypes] & HK_LIB_ELLEKIT) ? [HKSubstitutor substitutorWithTypes:HK_LIB_ELLEKIT] : NULL;

    // C-function groups: the HK_Library pref picks the backend here —
    // fishhook by default (clean prologues), any selectable backend when
    // explicitly chosen (stale substrate/substitute prefs fall back to
    // fishhook). Swift is a vtable-only API with no function hooks, so it
    // can never be a C-function backend.
    HKSubstitutor* subCFunc = subFish ? subFish : subMain;

    if(hooklibs && !(hooklibs & HK_LIB_SWIFT)) {
        subCFunc = [HKSubstitutor substitutorWithTypes:hooklibs];
    }

    // dlsym/dladdr group: inline-first — inline trampolines are
    // denyFishHook-immune, so IOSSecuritySuite's denyFishHook("dladdr")
    // cannot un-rebind the hide. The concealment must not depend on knowing
    // a detector (name-based detection is gone), so the pair never rides on
    // a detector flag. Fishhook (via subCFunc) only when ElleKit is
    // unavailable. Tradeoff: inline trampolines are prologue-detectable.
    HKSubstitutor* subSymLookup = subInline ? subInline : subCFunc;

    // dlopen_internal is a private libdyld symbol fishhook can't rebind:
    // inline only, always (never fishhook — see subInline comment).
    HKSubstitutor* subDyldExtra = subInline ? subInline : subMain;

    // Batching must be enabled per instance; the HK*Batching macros below
    // only touch the default substitutor (subMain). subCFunc may be a fresh
    // pref-selected instance — setBatching: is idempotent, so no dedup needed.
    [subMain setBatching:YES];
    [subFish setBatching:YES];
    [subInline setBatching:YES];
    [subCFunc setBatching:YES];
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
    _shdw_pref_filesystem = [prefs_load[@"Hook_Filesystem"] boolValue];
    _shdw_pref_fakemac = [prefs_load[@"Hook_FakeMac"] boolValue];
    _shdw_pref_hideapps = [prefs_load[@"Hook_HideApps"] boolValue];

    // The watcher only runs when a hook group needs it: the UIKit-class
    // groups (urlscheme/foundation prefs + an ObjC backend). Detection
    // escalation no longer routes through the watcher — it is purely
    // behavioral (tripwires call shdw_detector_detected directly), so a
    // watcher with nothing left to do stays disabled.
    _shdw_watcher_enabled = objcBackendAvailable && (_shdw_pref_urlscheme || _shdw_pref_foundation);
    _shdw_watcher_main = subMain;
    _shdw_watcher_cfunc = subCFunc;
    _shdw_watcher_inline = subInline;

    // shdw_detector_present cannot be YES here: only shdw_detector_detected
    // sets it, and no hook body can run before the installs below complete.
    // _shdw_escalation_installed therefore stays NO so the first behavioral
    // tripwire runs the full escalation (vnode re-arm, dyldextra, tier-2).
    #endif

    // Identity concealment, installed for every enabled app: the dyld image
    // routing surface must not depend on a detector being identified by name
    // or on the user leaving this toggle on — a jailbreak-scanning app sees
    // the dyld image list either way, so the toggle must not be able to
    // leave the surface exposed. _shdw_dyld_installed keeps the behavioral
    // tripwire escalation (shdw_detector_detected) from double-hooking.
    NSLog(@"+ dylib");

    shadowhook_dyld(subCFunc);

    #ifdef hookkit_h
    _shdw_dyld_installed = YES;
    #endif

    if([prefs_load[@"Hook_Filesystem"] boolValue]) {
        NSLog(@"+ filesystem");

        // C-level file hooks are tier 1 (they are also the probe tripwire).
        // The ObjC groups (NSFileManager etc.) install on detector evidence —
        // see shdw_install_tier2.
        shadowhook_libc(subCFunc);
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

        setenv("SHELL", "/bin/sh", 1);

        // C0-4: activate the envvar group. The filtering body is implemented
        // by the libc lane; until then the group installs no hooks and is a
        // safe no-op. subCFunc: fishhook by default (clean prologues — the
        // envvar getter must stay indistinguishable from stock).
        shadowhook_libc_envvar(subCFunc);
        // NSProcessInfo caches the launch environment at its first access (the
        // ctor touched it above), so the -environment/-arguments hooks must
        // install before app code can read the cached snapshot — ctor-time,
        // not tier-2. subMain: ObjC-method swizzles.
        shadowhook_NSProcessInfo(subMain);
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

    // Identity concealment, installed for every enabled app: the ObjC
    // runtime surface (objc_copyImageNames etc.) must not be pref-gated, for
    // the same reason as the dyld group above. Fail-soft: without an
    // ObjC-capable backend the swizzles would fail at hook time anyway — log
    // once and skip, never crash (see objcBackendAvailable above). The
    // backend guard also makes the tripwire escalation idempotent.
    NSLog(@"+ objc");

    if(objcBackendAvailable) {
        // libobjc C functions (objc_copyImageNames etc.) are exported symbols
        // fishhook could rebind, but the runtime calls some of them directly
        // in hot paths — keep them inline via subMain to be safe.
        shadowhook_objc(subMain);

        #ifdef hookkit_h
        _shdw_objc_installed = YES;
        #endif
    }

    if([prefs_load[@"Hook_Syscall"] boolValue]) {
        NSLog(@"+ syscall");

        shadowhook_syscall(subCFunc);
    }

    if([prefs_load[@"Hook_Memory"] boolValue]) {
        NSLog(@"+ memory");

        shadowhook_mem(subCFunc);
    }

    if([prefs_load[@"Hook_Sandbox"] boolValue]) {
        NSLog(@"+ sandbox");

        shadowhook_sandbox(subCFunc);
    }

    // Identity concealment, installed for every enabled app: the tweak-class
    // hiding surface must not be pref-gated (same reasoning as the dyld
    // group above). Fail-soft on the backend like the objc group above.
    NSLog(@"+ classes");

    if(objcBackendAvailable) {
        // Same reasoning as shadowhook_objc above: C-function hooks in the
        // runtime path stay on subMain.
        shadowhook_objc_hidetweakclasses(subMain);

        #ifdef hookkit_h
        _shdw_tweakclasses_installed = YES;
        #endif
    }

    // Identity concealment, installed for every enabled app: public symbol /
    // address lookup answers (dlsym/dladdr) must not be pref-gated (same
    // reasoning as the dyld group above). Backend: inline-first
    // (denyFishHook-immune) with fishhook fallback when ElleKit is missing —
    // see subSymLookup above; the hide never depends on knowing a detector.
    NSLog(@"+ dlsym");

    shadowhook_dyld_symlookup(subSymLookup);
    shadowhook_dyld_symaddrlookup(subSymLookup);

    #ifdef hookkit_h
    _shdw_symlookup_installed = YES;
    #endif

    if([prefs_load[@"Hook_DynamicLibrariesExtra"] boolValue] || shdw_detector_present) {
        NSLog(@"+ dylibex");

        // dlopen_internal is a private libdyld symbol fishhook can't rebind —
        // inline only. On a fishhook-only device subDyldExtra falls back to a
        // non-inline substitutor that cannot rebind it — skip, fail-soft
        // (same guard as the escalation site in shdw_detector_detected).
        if(!subInline) {
            NSLog(@"[Shadow] dylibex skipped: no inline backend (dlopen_internal needs one)");
        } else {
            shadowhook_dyld_extra(subDyldExtra);

            #ifdef hookkit_h
            _shdw_dyldextra_installed = YES;
            #endif
        }
    }

    #ifdef hookkit_h
    // Replay the already-loaded images into the watcher. The add-image
    // callback was registered at the top of this ctor — before any hooking,
    // so it sits on dyld's real list — and dyld's registration-time replay
    // ran while _shdw_watcher_enabled was still NO, discarding every
    // already-loaded image (UIKit among them). Deliver them now that the
    // flag is on. No image is delivered twice: the registration-time replay
    // ran while the flag was NO, dyld never re-replays, and the per-group
    // guard inside the callback (_shdw_uikit_installed) makes any duplicate
    // delivery a no-op; _shdw_watcher_started keeps this single-shot
    // regardless.
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

    // Post-install verification: log any hook that failed to install (see
    // the shadowhook_libc*_verify functions) so a silent no-op surfaces.
    if([prefs_load[@"Hook_Filesystem"] boolValue]) {
        shadowhook_libc_verify();
    }

    if([prefs_load[@"Hook_EnvVars"] boolValue]) {
        shadowhook_libc_envvar_verify();
    }

    if([prefs_load[@"Hook_LowLevelC"] boolValue]) {
        shadowhook_libc_lowlevel_verify();
    }

    if([prefs_load[@"Hook_AntiDebugging"] boolValue]) {
        shadowhook_libc_antidebugging_verify();
    }

    if([prefs_load[@"Hook_Syscall"] boolValue]) {
        shadowhook_syscall_verify();
    }

    if([prefs_load[@"Hook_Memory"] boolValue]) {
        shadowhook_mem_verify();
    }

    if([prefs_load[@"Hook_MachBootstrap"] boolValue]) {
        shadowhook_mach_verify();
    }

    if([prefs_load[@"Hook_Sandbox"] boolValue]) {
        shadowhook_sandbox_verify();
    }

    // The dyld groups install unconditionally (identity concealment).
    shadowhook_dyld_verify();
    shadowhook_dyld_symlookup_verify();
    shadowhook_dyld_symaddrlookup_verify();

    if([prefs_load[@"Hook_DynamicLibrariesExtra"] boolValue] || shdw_detector_present) {
        shadowhook_dyld_extra_verify();
    }
    #endif
    } @catch (NSException* e) {
        NSLog(@"[Shadow] hook install failed: %@ — continuing unhooked", e);
        return;
    }

    // Crash watchdog: the ctor completed — the payload loaded successfully.
    // Clear the crash counter so the next launch starts fresh.
    NSString* counterKey = shdw_crash_counter_key();
    if(counterKey) {
        NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
        [defaults removeObjectForKey:counterKey];
        [defaults synchronize];
    }

    NSLog(@"completed hooks");
}

%dtor {
    // Best-effort lease release at process teardown. The daemon also watches
    // the service-port send right, so this is courtesy only.
    shadowhook_vnode_release();
}
