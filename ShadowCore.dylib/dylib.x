#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import "../common.h"
#import <Shadow/JBPath.h>
#import "hooks/hooks.h"

#import <Shadow.h>
#import <Shadow/Settings.h>
#import <libSandy.h>
#import <HookKit.h>

#import "HookCoordinator.h"   // B2a: coordinator installer table + ctor gate


#import "../vendor/apple/dyld_priv.h"   // dyld_image_path_containing_address

// Set only by shdw_detector_detected, which the behavioral tripwires in the
// hook files (JB-indicator path/symbol/dylib probes by non-tweak callers)
// invoke — never by image-name matching. Consumed by the vnode hiding gate
// (vnode.x) and by the hook-backend routing below.
BOOL shdw_detector_present = NO;

// Emergency kill-switch for the dyld_all_image_infos memory-hiding patch
// (AR2). Default YES (patch on); set from the MemoryLevelHiding pref in the
// ctor before shadowhook_dyld installs, so a misbehaving patch on a new iOS
// can be disabled without a reinstall (see hooks.h).
BOOL shdw_memory_hiding_enabled = YES;

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
#ifndef SHADOW_LEGACY_COORDINATOR
static BOOL _shdw_watcher_started = NO;      // single-shot replay guard (legacy replay only)
#endif
static BOOL _shdw_objc_backend = NO;         // ElleKit/Substrate/Substitute available
static BOOL _shdw_pref_urlscheme = NO;
static BOOL _shdw_pref_foundation = NO;
static BOOL _shdw_pref_filesystem = NO;
static BOOL _shdw_pref_fakemac = NO;
static BOOL _shdw_pref_hideapps = NO;
// B2b: _shdw_dyld_installed / _shdw_symlookup_installed are provably
// write-only (set at the ctor's install sites, read NOWHERE — no hooks, no
// escalation, no coordinator). The coordinator path (SHADOW_LEGACY_COORDINATOR
// defined) does not need them and does not declare them; the legacy path
// keeps them verbatim.
#ifndef SHADOW_LEGACY_COORDINATOR
static BOOL _shdw_dyld_installed = NO;       // set when the ctor installed the group
static BOOL _shdw_symlookup_installed = NO;
#endif
static BOOL _shdw_dyldextra_installed = NO;
static BOOL _shdw_uikit_installed = NO;      // UIKit groups installed
// C1: _shdw_escalation_installed stays declared in BOTH paths — the legacy
// body (including the coordinator-init-failed fall-through) reads/writes it.
static BOOL _shdw_escalation_installed = NO; // detector escalation handled
static BOOL _shdw_tier2_installed = NO;      // ObjC groups installed on first probe
static BOOL _shdw_objc_installed = NO;       // C0-4: shadowhook_objc group installed
static BOOL _shdw_tweakclasses_installed = NO; // C0-4: hidetweakclasses group installed
static HKSubstitutor* _shdw_watcher_main = nil;   // subMain
static HKSubstitutor* _shdw_watcher_cfunc = nil;  // subCFunc
static HKSubstitutor* _shdw_watcher_inline = nil; // subInline (inline escalation)

static void shdw_install_tier2(void);  // defined with shdw_detector_detected

// C1: forward declaration — the coordinator instance is created by the ctor
// dispatch (defined below with the installer table) and consumed by
// shdw_detector_detected's escalation routing above.
#ifdef SHADOW_LEGACY_COORDINATOR
static SHDWHookCoordinator* shdw_coordinator_instance;
#endif

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
            // C2: the coordinator path routes the UIKit-load INSTALL through
            // the coordinator — record the event, then the planner's
            // SHDWEventUIKitLoaded install (Hook_URLScheme +
            // Hook_Foundation@uikit, pref-gated via prefKey, message-gated
            // via SHDWCapMessage, idempotent via the bitset). The legacy
            // body below stays byte-identical under #ifndef.
            #ifdef SHADOW_LEGACY_COORDINATOR
            if(shdw_coordinator_instance) {
                [shdw_coordinator_instance recordUIKitImageLoad];
                [shdw_coordinator_instance installEvent:SHDWEventUIKitLoaded];
                _shdw_uikit_installed = YES;
                return;
            }

            // Coordinator init failed at ctor: fall through to the legacy
            // body (fail-soft).
            #endif

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
    // C1: the coordinator path (SHADOW_LEGACY_COORDINATOR defined) routes the
    // INSTALL response through the coordinator — planner-driven escalation
    // install, idempotent via the coordinator's _escalated flag + installed-
    // state bitset. Evidence bookkeeping (detector log, shdw_detector_present,
    // vnode re-arm) is mirrored here verbatim so the coordinator path behaves
    // identically. The legacy path compiles this block out entirely and runs
    // the original body below byte-identical.
    #ifdef SHADOW_LEGACY_COORDINATOR
    if(shdw_coordinator_instance) {
        NSLog(@"[Shadow] detector probe: %s", reason ?: "unknown");

        shdw_detector_present = YES;

        // Detector activity log (diagnostic) — mirror of the legacy block.
        @try {
            NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
            NSMutableArray* log = [[defaults arrayForKey:@"DetectorLog"] mutableCopy] ?: [NSMutableArray new];

            NSDateFormatter* fmt = [NSDateFormatter new];
            fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss";
            [log addObject:[NSString stringWithFormat:@"%@  %@  %@", [fmt stringFromDate:[NSDate date]], [NSString stringWithUTF8String:reason ?: "unknown"], [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown"]];

            if(log.count > 100) {
                [log removeObjectsInRange:NSMakeRange(0, log.count - 100)];
            }

            [defaults setObject:log forKey:@"DetectorLog"];
            [defaults synchronize];
        } @catch (NSException* e) {
            // Never let diagnostics break the bypass.
        }

        // Vnode client re-arm (same as legacy): a detector that appeared
        // after the ctor's gate check still triggers the acquire.
        shadowhook_vnode(NULL);

        [shdw_coordinator_instance escalateWithReason:reason ? [NSString stringWithUTF8String:reason] : @"unknown"];
        return;
    }

    // Coordinator init failed at ctor: fall through to the legacy body so
    // the escalation still arms (fail-soft).
    #endif

    if(_shdw_escalation_installed) {
        return;
    }

    _shdw_escalation_installed = YES;

    NSLog(@"[Shadow] detector probe: %s", reason ?: "unknown");

    shdw_detector_present = YES;

    // Detector activity log (diagnostic): append the probe to the prefs
    // suite so the settings pane can show recent hits. Best-effort — a
    // prefs failure must never break the escalation below. Capped at 100
    // entries, newest last.
    @try {
        NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
        NSMutableArray* log = [[defaults arrayForKey:@"DetectorLog"] mutableCopy] ?: [NSMutableArray new];

        NSDateFormatter* fmt = [NSDateFormatter new];
        fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss";
        [log addObject:[NSString stringWithFormat:@"%@  %@  %@", [fmt stringFromDate:[NSDate date]], [NSString stringWithUTF8String:reason ?: "unknown"], [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown"]];

        if(log.count > 100) {
            [log removeObjectsInRange:NSMakeRange(0, log.count - 100)];
        }

        [defaults setObject:log forKey:@"DetectorLog"];
        [defaults synchronize];
    } @catch (NSException* e) {
        // Never let diagnostics break the bypass.
    }

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
        shadowhook_NSUserDefaults(_shdw_watcher_main);
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

// ---------------------------------------------------------------------------
// B2a: coordinator installer table + legacy-flag gate.
//
// SHADOW_LEGACY_COORDINATOR — compile-time rollback switch. Default UNSET:
// the ctor below runs EXACTLY as it always has (the coordinator table and
// dispatch below still compile, but are never invoked). When the flag IS
// defined (e.g. `make -C ShadowCore.dylib
// ADDITIONAL_CFLAGS="-DSHADOW_LEGACY_COORDINATOR"`), the ctor hands the
// install orchestration to the coordinator INSTEAD of the legacy block —
// only one path can install hooks at runtime. The legacy block remains in
// the binary, compiled and dead, so flipping the flag back is a pure
// rebuild.
//
// Rows are in the EXACT SHDWInstallUnits() order (the canonical install
// order, see Shadow.framework/HookConfiguration.m); each row REFERENCES the
// legacy shadowhook_* functions the ctor calls. A few units have no single
// legacy function (their legacy install = several shadowhook_* calls), so
// the row points at a thin dylib.x-side wrapper that calls the legacy
// functions in the same order and with the same backend role the ctor used.
// The wrappers also carry each group's non-hook side effects (envvar
// sanitization) so the coordinator path is behaviorally identical to the
// legacy ctor pass.
//
// Multi-function units (row → legacy calls):
//   symlookup        → shadowhook_dyld_symlookup + shadowhook_dyld_symaddrlookup (both on subSymLookup)
//   Hook_Filesystem@objc → shadowhook_NSFileManager/NSFileHandle/NSFileVersion/NSFileWrapper (subMain)
//   Hook_Foundation@objc → shadowhook_NSArray/NSDictionary/NSBundle/NSString/NSURL/NSData/NSThread/NSUserDefaults (subMain)
// Verify rows mirror the ctor's verify pass (dylib.x:667-712) per unit.
// ---------------------------------------------------------------------------

#ifdef SHADOW_LEGACY_COORDINATOR

// C1: the coordinator instance, shared between the ctor pass and the
// detector-escalation path (shdw_detector_detected). Created once by
// shdw_coordinator_ctor; retained for the process lifetime. (Forward
// declared above for shdw_detector_detected.)
static SHDWHookCoordinator* shdw_coordinator_instance = nil;

static void shdw_coord_dyld(HKSubstitutor* hooks) {
    shadowhook_dyld(hooks);
}

static void shdw_coord_envvars_c(HKSubstitutor* hooks) {
    // Legacy inline envvar sanitization (dylib.x:488-511), preserved
    // verbatim so the coordinator path behaves identically.
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

    shadowhook_libc_envvar(hooks);
    shadowhook_envpolicy(hooks);   // setenv/unsetenv: PATH sanitization cache invalidation
    shadowhook_NSProcessInfo(hooks);   // legacy: subMain (ObjC swizzles)
}

static void shdw_coord_symlookup(HKSubstitutor* hooks) {
    shadowhook_dyld_symlookup(hooks);
    shadowhook_dyld_symaddrlookup(hooks);
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
}

static void shdw_coord_verify_envvars(void) {
    shadowhook_libc_envvar_verify();
}

static void shdw_coord_verify_symlookup(void) {
    shadowhook_dyld_symlookup_verify();
    shadowhook_dyld_symaddrlookup_verify();
}

// EXACT SHDWInstallUnits() order (21 rows). install/verify reference the
// legacy shadowhook_* functions — no bodies moved.
static const SHDWHookInstaller kSHDWCoordinatorInstallers[] = {
    { "dyld",                         shdw_coord_dyld,                 shadowhook_dyld_verify },
    { "Hook_Filesystem@c",            shadowhook_libc,                 shadowhook_libc_verify },
    { "Hook_EnvVars@c",               shdw_coord_envvars_c,            shdw_coord_verify_envvars },
    { "Hook_EnvVars@objc",            shadowhook_NSProcessInfo,        NULL },
    { "Hook_DeviceCheck",             shadowhook_DeviceCheck,          NULL },
    { "Hook_MachBootstrap",           shadowhook_mach,                 shadowhook_mach_verify },
    { "Hook_IOKit",                   shadowhook_iokit,                shadowhook_iokit_verify },
    { "Hook_LowLevelC",               shadowhook_libc_lowlevel,        shadowhook_libc_lowlevel_verify },
    { "Hook_AntiDebugging",           shadowhook_libc_antidebugging,   shadowhook_libc_antidebugging_verify },
    { "objc",                         shadowhook_objc,                 NULL },
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

// Coordinator ctor dispatch: the flag-gated replacement for the legacy ctor
// install/verify block. Runs the coordinator's planner-driven ctor pass.
static void shdw_coordinator_ctor(NSDictionary<NSString*, id>* prefs_load) {
    if(!shdw_coordinator_instance) {
        shdw_coordinator_instance =
            [[SHDWHookCoordinator alloc] initWithInstallerTable:kSHDWCoordinatorInstallers
                                                          count:sizeof(kSHDWCoordinatorInstallers) / sizeof(kSHDWCoordinatorInstallers[0])
                                                          prefs:prefs_load];
    }

    if(!shdw_coordinator_instance) {
        NSLog(@"[Shadow][coordinator] init failed — running legacy ctor path");
        return;
    }

    // The legacy ctor runs the envvar sanitization + installs as one block;
    // the coordinator runs the planner pass, which installs every
    // ctorInstall unit in SHDWInstallUnits() order (including the identity
    // groups), one v2 batch at the end.
    [shdw_coordinator_instance installEvent:SHDWEventCtor];
}

#endif // SHADOW_LEGACY_COORDINATOR

%ctor {
    // Fail-soft: any unexpected NSException from this ctor — watcher
    // registration, prefs read, daemon lease, hook install, image replay —
    // must not crash the app at spawn. Log and continue unhooked (the verify
    // functions below surface what failed to install).
    @try {
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

    // Emergency kill-switch (AR2): the dyld_all_image_infos memory-hiding
    // patch is unconditional by default, but a misbehaving patch on a new iOS
    // must be disableable without a reinstall. Read the pref here — before
    // shadowhook_dyld installs — so dyld.x can skip patching / restore the
    // original struct. Default YES (patch on).
    shdw_memory_hiding_enabled = [prefs_load[@"MemoryLevelHiding"] boolValue];

    // B2a: coordinator takeover (compile-time rollback). When
    // SHADOW_LEGACY_COORDINATOR is defined (e.g. via
    // `make -C ShadowCore.dylib ADDITIONAL_CFLAGS="-DSHADOW_LEGACY_COORDINATOR"`)
    // the coordinator installs the ctor pass instead of the legacy block
    // below; otherwise the legacy block runs untouched. Both paths compile;
    // only one runs. (Ordered after the MemoryLevelHiding read above so the
    // coordinator's shadowhook_dyld sees the resolved kill-switch pref —
    // dyld.x reads shdw_memory_hiding_enabled inside shadowhook_dyld.)
    #ifdef SHADOW_LEGACY_COORDINATOR
    shdw_coordinator_ctor(prefs_load);
    #endif

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
    //
    // B2c: pass the resolved effective preference (prefs_load already
    // applies per-app override → global → shipped default, matching
    // vnode.x's own plist resolution exactly) so vnode.x stops re-reading
    // the plist. Identical in both flag states.
    shdw_vnode_set_pref_enabled([prefs_load[@"VnodeHiding"] boolValue]);
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

    // subMain: message-capable backend via category API. substitutorWithCategory:
    // picks the first available backend that supports HK_CAT_MESSAGE (ElleKit,
    // Substrate, Substitute, or native — in that priority order). This replaces
    // the old explicit availability-bitmask logic: the category API encapsulates
    // the priority order and availability check, so the caller only states the
    // capability requirement. The HK_Library pref never configures subMain:
    // fishhook cannot swizzle ObjC methods, so applying the pref here silently
    // broke every ObjC group. Never setTypes: on subMain.
    hookkit_cat_t available_categories = [HKSubstitutor getAvailableCategories];
    BOOL objcBackendAvailable = (available_categories & HK_CAT_MESSAGE) != 0;

    // subMain: when a message-capable backend is available, use the category
    // picker; otherwise fall back to defaultSubstitutor (fishhook-only, which
    // will cause ObjC groups to fail gracefully at hook time — logged below).
    HKSubstitutor* subMain = objcBackendAvailable
        ? [HKSubstitutor substitutorWithCategory:HK_CAT_MESSAGE]
        : [HKSubstitutor defaultSubstitutor];

    if(!objcBackendAvailable) {
        NSLog(@"[Shadow] no ObjC-capable hooking library available (only fishhook); skipping ObjC-method hook groups");
    }

    // subFish: function-rebind backend via category API. substitutorWithCategory:
    // picks the first available backend that supports HK_CAT_FUNCTION_REBIND
    // (fishhook by priority — clean prologues, no trampoline detection surface).
    // C-function hooks that detectors call route through this. Falls to NULL
    // when no rebind-capable backend is available.
    HKSubstitutor* subFish = [HKSubstitutor substitutorWithCategory:HK_CAT_FUNCTION_REBIND];

    // subInline: function-inline backend via category API. Installs trampolines
    // in function prologues (ldr x16, #imm; br x16), so amIMSHooked-style
    // prologue scanners can spot them — but denyFishHook("dladdr") cannot
    // un-rebind inline hooks, and fishhook can't reach private symbols like
    // dlopen_internal. Used for dlopen_internal always, and inline-first for
    // the dlsym/dladdr pair (see subSymLookup below). Falls to NULL when no
    // inline-capable backend is available.
    HKSubstitutor* subInline = [HKSubstitutor substitutorWithCategory:HK_CAT_FUNCTION_INLINE];

    // C-function groups: the HK_Library pref picks the backend here —
    // fishhook by default (clean prologues), any selectable backend when
    // explicitly chosen (stale substrate/substitute prefs fall back to
    // fishhook). Swift is a vtable-only API with no function hooks, so it
    // can never be a C-function backend.
    HKSubstitutor* subCFunc = subFish ? subFish : subMain;

    if(hooklibs && !(hooklibs & HK_LIB_SWIFT)) {
        subCFunc = [HKSubstitutor substitutorWithTypes:hooklibs];
    }

    // dlsym/dladdr group: inline-first via category API.
    // substitutorWithOrderedCategories: tries HK_CAT_FUNCTION_INLINE first
    // (inline trampolines are denyFishHook-immune, so IOSSecuritySuite's
    // denyFishHook("dladdr") cannot un-rebind the hide), then falls back
    // within the category API to HK_CAT_FUNCTION_REBIND (fishhook) before the
    // subCFunc safety net. The concealment must not depend on knowing a
    // detector (name-based detection is gone), so the pair never rides on a
    // detector flag. Behavioral delta: on devices with no inline backend but
    // a pref-selected substrate/substitute, the fallback now lands on
    // FUNCTION_REBIND (fishhook) before subCFunc — intended, since
    // dlsym/dladdr concealment prefers rebind over an unpinned inline-capable
    // pref backend. Tradeoff: inline trampolines are prologue-detectable.
    // B2b: subSymLookup/subDyldExtra are consumed ONLY by the legacy install
    // block (compiled out under SHADOW_LEGACY_COORDINATOR) — the coordinator
    // path resolves its own symlookup/private-symbol backends, so the
    // declarations are excluded with the block (-Werror unused-variable).
    #ifndef SHADOW_LEGACY_COORDINATOR
    HKSubstitutor* subSymLookup = [HKSubstitutor substitutorWithOrderedCategories:@[@(HK_CAT_FUNCTION_INLINE), @(HK_CAT_FUNCTION_REBIND)]] ?: subCFunc;

    // dlopen_internal is a private libdyld symbol fishhook can't rebind:
    // private-symbol-capable backend only, always (never fishhook).
    // substitutorWithOrderedCategories: tries HK_CAT_PRIVATE_SYMBOL first,
    // then HK_CAT_MESSAGE (message-capable backends can also reach private
    // symbols), before falling back to subMain — the guard below skips the
    // group when no such backend exists.
    HKSubstitutor* subDyldExtra = [HKSubstitutor substitutorWithOrderedCategories:@[@(HK_CAT_PRIVATE_SYMBOL), @(HK_CAT_MESSAGE)]] ?: subMain;
    #endif

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
    #ifndef SHADOW_LEGACY_COORDINATOR
    HKSubstitutor* subSymLookup = NULL;
    HKSubstitutor* subDyldExtra = NULL;
    #endif
    #endif

    // Stash state for the spawn-time watcher (shdw_early_image_add): it runs
    // on dyld's loader thread for images loaded after this ctor and needs the
    // substitutors/prefs without touching ctor locals.
    #ifdef hookkit_h
    _shdw_objc_backend = objcBackendAvailable;
    _shdw_pref_urlscheme = [prefs_load[@"Hook_URLScheme"] boolValue];
    _shdw_pref_foundation = [prefs_load[@"Hook_Foundation"] boolValue];
    _shdw_pref_filesystem = [prefs_load[@"Hook_Filesystem"] boolValue];
    // B2b: Hook_FakeMac is a stale, accepted-but-ignored key — the FakeMac
    // group was removed as inert (its installer installs nothing). The
    // legacy path still reads it into _shdw_pref_fakemac verbatim; the
    // coordinator path skips the read entirely (no-op).
    #ifndef SHADOW_LEGACY_COORDINATOR
    _shdw_pref_fakemac = [prefs_load[@"Hook_FakeMac"] boolValue];
    #endif
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

    // C2: coordinator-path replay of already-loaded images. The legacy
    // replay (below, #ifndef-guarded) delivers the ctor-time image list once
    // the watcher is enabled; the coordinator path mirrors it so a UIKit
    // already loaded at ctor time still reaches the coordinator's UIKit
    // install (recordUIKitImageLoad + SHDWEventUIKitLoaded via
    // shdw_early_image_add, which routes to the coordinator under the flag).
    // Single-shot by construction (the ctor runs once); idempotence inside
    // the callback (_shdw_uikit_installed / coordinator bitset) makes any
    // duplicate delivery a no-op.
    #ifdef SHADOW_LEGACY_COORDINATOR
    if(_shdw_watcher_enabled) {
        uint32_t replay_count = _dyld_image_count();

        for(uint32_t i = 0; i < replay_count; i++) {
            shdw_early_image_add(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
        }
    }
    #endif

    // B2b: the legacy install block below is dead in the coordinator path
    // (SHADOW_LEGACY_COORDINATOR defined — shdw_coordinator_ctor above
    // already installed the ctor pass via the planner). Compile it out so
    // the coordinator path carries no duplicate install/verify gates and no
    // write-only global writes; the flag-unset build keeps it verbatim.
    #ifndef SHADOW_LEGACY_COORDINATOR

    // Identity concealment, installed for every enabled app: the dyld image
    // routing surface must not depend on a detector being identified by name
    // or on the user leaving this toggle on — a jailbreak-scanning app sees
    // the dyld image list either way, so the toggle must not be able to
    // leave the surface exposed. _shdw_dyld_installed keeps the behavioral
    // tripwire escalation (shdw_detector_detected) from double-hooking.
    NSLog(@"+ dylib");

    shadowhook_dyld(subCFunc);

    #if defined(hookkit_h) && !defined(SHADOW_LEGACY_COORDINATOR)
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
        // setenv/unsetenv: clear the PATH sanitization cache (EnvironmentPolicy.m).
        shadowhook_envpolicy(subCFunc);
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

    if([prefs_load[@"Hook_IOKit"] boolValue]) {
        NSLog(@"+ iokit");

        shadowhook_iokit(subCFunc);
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

    #if defined(hookkit_h) && !defined(SHADOW_LEGACY_COORDINATOR)
    _shdw_symlookup_installed = YES;
    #endif

    if([prefs_load[@"Hook_DynamicLibrariesExtra"] boolValue] || shdw_detector_present) {
        NSLog(@"+ dylibex");

        // dlopen_internal is a private libdyld symbol fishhook can't rebind —
        // private-symbol-capable backend only. If the category yielded no such
        // backend (subDyldExtra fell back to subMain), skip — fail-soft (same
        // guard as the escalation site in shdw_detector_detected).
        if(subDyldExtra == subMain) {
            NSLog(@"[Shadow] dylibex skipped: no private-symbol-capable backend (dlopen_internal needs one)");
        } else {
            shadowhook_dyld_extra(subDyldExtra);

            #ifdef hookkit_h
            _shdw_dyldextra_installed = YES;
            #endif
        }
    }

    // Drain the batch BEFORE the image replay. HookKit v2 batching writes
    // original pointers only at executeHooks; the replay's path checks call
    // into the engine (e.g. objc_getMetaClass via NSClassFromString), which
    // would hit a hooked replacement whose original is still NULL and crash
    // (SIGSEGV at PC=0 — observed on-device). With batching disabled, the
    // replay's UIKit-group installs apply immediately, each writing its own
    // original — no use-before-drain window.
    // NOTE: the objc/classes hooks (objc_getMetaClass etc.) ride on subMain,
    // which is a separate instance from the default substitutor — the
    // HK*Batching macros only touch the default, so drain subMain explicitly
    // or its originals stay NULL (same crash, different lane).
    [subMain executeHooks];
    [subMain setBatching:NO];
    [subFish executeHooks];
    [subFish setBatching:NO];
    [subInline executeHooks];
    [subInline setBatching:NO];
    HKExecuteBatch();
    HKDisableBatching();

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

    if([prefs_load[@"Hook_IOKit"] boolValue]) {
        shadowhook_iokit_verify();
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
    #endif // hookkit_h
    #endif // SHADOW_LEGACY_COORDINATOR (B2b: legacy install/verify block)
    } @catch (NSException* e) {
        NSLog(@"[Shadow] constructor failed: %@ — continuing unhooked", e);
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
