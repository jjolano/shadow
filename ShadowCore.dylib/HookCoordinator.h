// HookCoordinator — additive lifecycle coordinator for Shadow's hook install
// orchestration (rewrite of the legacy dylib.x %ctor flow).
//
// B1 scope: the coordinator is built and compiled into ShadowCore, but it is
// OPT-IN — dylib.x keeps its own install flow and nothing routes through this
// module yet. Step B2 wires dylib.x to it (see "B2 handoff" below); until
// then, this module changes no runtime behavior.
//
// The coordinator is the v2 (HookKit category API) replacement for the
// hand-rolled backend chain in dylib.x:329-394:
//   - message backend   ←  HK_CAT_MESSAGE (legacy: substitutorWithCategory:)
//   - rebind backend    ←  HK_CAT_FUNCTION_REBIND (legacy: subFish)
//   - inline/auto-cover ←  HK_CAT_FUNCTION_INLINE (legacy: subInline) — used
//                          via substitutorWithAutoCoverCategories:
//                          @[HK_CAT_FUNCTION_INLINE, HK_CAT_FUNCTION_REBIND]
//                          (v2: per-hook preflight routing instead of a pinned
//                          single-technique backend)
//   - symlookup backend ←  substitutorWithAutoCoverCategories:
//                          @[HK_CAT_FUNCTION_INLINE, HK_CAT_FUNCTION_REBIND]
//                          (legacy: subSymLookup — same priority, v2 API)
//   - private-symbol    ←  native, then PRIVATE_SYMBOL/MESSAGE fallback
//                          (legacy: subDyldExtra)
//
// The resolved backend set is computed ONCE at init and mirrored in
// SHDWCapabilities so the planner (SHDWHookPlan) gates units on the same
// capability view the coordinator installs with.
//
// Capability gating mirrors the legacy flow exactly:
//   - message groups (objc, classes, tier-2, uikit) fail-soft without a
//     message-capable backend — the planner drops them (SHDWCapMessage);
//   - symlookup (inline-first/rebind) and the C-function groups never gate
//     (legacy: subCFunc always resolves to something);
//   - the dlopen_internal group (phase escalation) is backend-gated HERE, at
//     install time, exactly like legacy subDyldExtra==subMain skip — the
//     planner deliberately does not gate it (SHDWUnitCapable returns YES for
//     escalation units) so the coordinator's skip log is the single source.
//
// Batching (v2 setBatching:/executeHooks): one batch per lifecycle event —
// ctor tier, UIKit load, detector escalation. HK_ERR_PARTIAL from
// executeHooks means some-but-not-all operations installed; the coordinator
// logs it and the per-unit verify functions (legacy shadowhook_*_verify)
// surface exactly which hooks missed, mirroring the legacy post-install
// verify pass. Each backend instance handed to an installer owns and drains
// its queue; HookKit groups auto-cover operations by their winning backend.
//
// State: installed-state bitset (one bit per install unit, indexed by unit
// index in the SHDWInstallUnits() table) + a serial lifecycle dispatch queue
// (one event at a time; the UIKit image callback and the detector escalation
// may fire from dyld's loader thread / hooked-function context). The
// coordinator records image events (UIKit load detection); actual image
// watcher wiring arrives in a later step — dylib.x still owns
// _dyld_register_func_for_add_image.
//
// B2 handoff — what dylib.x must pass in when it cuts over:
//   - prefs:            the NSDictionary* prefs_load the ctor already reads;
//   - units:            SHDWInstallUnits() (the frozen metadata table);
//   - installers:       a table of (unitID, install, verify) function
//                       pointers — the legacy shadowhook_* functions are
//                       the installers; the coordinator calls
//                       install(backend) and verify() per unit;
//   - substitutors:     the coordinator owns backend resolution (v2 API);
//                       dylib.x keeps passing its own to the legacy ctor
//                       until the cutover deletes that block.
// The coordinator never touches dylib.x globals; it is fully parameterized
// by its initializer + the installer table, so the cutover is a mechanical
// replacement of the ctor body.

#ifndef hook_coordinator_h
#define hook_coordinator_h

#import <Foundation/Foundation.h>
#import <Shadow/HookConfiguration.h>
#import <HookKit/Compat.h>

#pragma mark - Installer table (what dylib.x supplies in step B2)

// One row = one install unit's legacy hook functions. unitID must match a
// unitID in the SHDWInstallUnits() table; install is the legacy
// shadowhook_* function (takes the backend HKSubstitutor*); verify is the
// legacy shadowhook_*_verify function (NULL when the unit has none).
typedef struct {
    const char* unitID;
    void (*install)(HKSubstitutor* hooks);
    void (*verify)(void);
} SHDWHookInstaller;

#pragma mark - Backend set (resolved once at init)

@interface SHDWBackendSet : NSObject
@property (nonatomic, readonly) HKSubstitutor* message;        // HK_CAT_MESSAGE
@property (nonatomic, readonly) HKSubstitutor* rebind;         // HK_CAT_FUNCTION_REBIND (subFish)
@property (nonatomic, readonly) HKSubstitutor* inlineCover;    // auto-cover: FUNCTION_INLINE → FUNCTION_REBIND
@property (nonatomic, readonly) HKSubstitutor* symlookup;      // auto-cover: FUNCTION_INLINE → FUNCTION_REBIND
@property (nonatomic, readonly) HKSubstitutor* privateSym;     // native, then PRIVATE_SYMBOL → MESSAGE
@property (nonatomic, readonly) SHDWCapabilities capabilities; // planner view of the same backends
@end

#pragma mark - Coordinator

@interface SHDWHookCoordinator : NSObject

// Resolves the v2 backend set once (activeType/activeStrategy read at init),
// derives SHDWCapabilities, and prepares the serial lifecycle queue. The
// installer table is copied; prefs is retained for planner calls. No hooks
// are installed by init.
- (instancetype)initWithInstallerTable:(const SHDWHookInstaller*)installers
                                 count:(NSUInteger)count
                                 prefs:(NSDictionary<NSString*, id>*)prefs;

@property (nonatomic, readonly) SHDWBackendSet* backends;
@property (nonatomic, readonly) NSDictionary<NSString*, id>* prefs;
@property (nonatomic, readonly) NSUInteger unitCount;
@property (nonatomic, readonly, getter=isEscalated) BOOL escalated;  // detector escalation ran

// Runs the units the planner ordered for the event, one batch per event.
// Idempotent per event: a unit already installed (bitset) is skipped even if
// a later event's plan names it again (legacy _shdw_*_installed guards).
// On HK_ERR_PARTIAL (or HK_ERR) from executeHooks, runs the verify functions
// of the units just attempted, mirroring the legacy post-install verify pass
// (the verify functions log which hooks missed). Returns the number of units
// installed this call (0 when none — e.g. all already installed or backend
// fail-soft).
- (NSUInteger)installEvent:(SHDWLifecycleEvent)event;

// Escalation fast path: arms the detector-escalation install pass (the
// tier-2 + dlopen_internal units). Equivalent to installEvent:
// SHDWEventDetectorEscalation, kept for call-site symmetry with the legacy
// shdw_detector_detected. Idempotent.
- (void)escalateWithReason:(NSString*)reason;

// UIKit image load record (image watcher wiring arrives in a later step —
// dylib.x still owns the actual callback registration). Records the event so
// installEvent: SHDWEventUIKitLoaded later installs the uikit units.
- (void)recordUIKitImageLoad;

// Installed-state query, per unit index in the SHDWInstallUnits() table.
- (BOOL)isUnitInstalledAtIndex:(NSUInteger)index;
- (BOOL)isUnitInstalledWithID:(NSString*)unitID;

@end

#endif // hook_coordinator_h
