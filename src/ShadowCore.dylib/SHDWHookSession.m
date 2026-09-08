#import "SHDWHookSession.h"
#import <HookKit/HookKitResults.h>
#import "hooks/Universal/rebind_slots.h"

#import <HookKit/HookKit.h>
#import <HookKit/HookKitArtifacts.h>
#import <HookKit/HookKitObjC.h>
#import <HookKit/HookKitResolver.h>

#include <dlfcn.h>
#include <string.h>

// Per-process function/memory backend override (HK_Library troubleshooting
// pref). Set once at ShadowCore init, before any hook runs; read per hook.
// Empty means "auto" — the runtime's own routing order.
static char gSHDWBackendOverride[128];

void SHDWSetProcessBackendOverride(const char* backendID) {
    if(backendID && backendID[0] && strcmp(backendID, "auto") != 0) {
        strlcpy(gSHDWBackendOverride, backendID, sizeof(gSHDWBackendOverride));
    } else {
        gSHDWBackendOverride[0] = '\0';
    }
}

// This constructor exists in newer HookKit sources but is not exported by all
// packaged builds. Resolve it dynamically so absence cleanly keeps auto routing.
typedef hk_status_t (*SHDWHKRuntimeCreateWithBackendOverride)(
    const hk_runtime_config_t*, const char*, hk_runtime_t**);

// Cells this session has published a continuation into. A failed attempt
// must never erase one: a live replacement may still chain through it. Any
// other cell holds caller input, which a failed attempt neutralizes to NULL.
#define SHDW_PUBLISHED_CELLS_MAX 512
static void* gSHDWPublishedCells[SHDW_PUBLISHED_CELLS_MAX];
// ponytail: fixed table like the IMP registries below; beyond the cap new
// cells are treated as unpublished (cleared on failure) until raised.
static uint32_t gSHDWPublishedCellCount;

static BOOL shdw_cell_holds_published_original(void** cell) {
    if(!cell) return NO;
    uint32_t count = __atomic_load_n(&gSHDWPublishedCellCount, __ATOMIC_ACQUIRE);
    for(uint32_t i = 0; i < count; i++) {
        if(gSHDWPublishedCells[i] == (void*)cell) return YES;
    }
    return NO;
}

static void shdw_note_published_cell(void** cell) {
    if(!cell || shdw_cell_holds_published_original(cell)) return;
    uint32_t count = __atomic_load_n(&gSHDWPublishedCellCount, __ATOMIC_ACQUIRE);
    if(count == SHDW_PUBLISHED_CELLS_MAX) return;
    gSHDWPublishedCells[count] = (void*)cell;
    __atomic_store_n(&gSHDWPublishedCellCount, count + 1, __ATOMIC_RELEASE);
}

static void shdw_clear_unpublished_cell(void** cell) {
    if(cell && !shdw_cell_holds_published_original(cell)) {
        *cell = NULL;
    }
}

static void shdw_finish_uninstalled_hook(hk_hook_t* hook, void** oldPtr,
                                         BOOL entryPublished,
                                         BOOL* outCleanRefusal) {
    hk_hook_result_t result;
    if(!hook || hk_hook_copy_result(hook, &result) != HK_STATUS_OK) {
        return;
    }
    // A proven no-mutation failure clears the cell unless it already held a
    // continuation from an earlier attempt: that one may still be live, but a
    // continuation published by this very attempt died with it.
    if(oldPtr && result.mutation == HK_MUTATION_NONE && !entryPublished) {
        *oldPtr = NULL;
    }
    if(outCleanRefusal) {
        *outCleanRefusal = hk_hook_result_refused_cleanly(&result);
    }
}

static void* shdw_prepared_original(hk_hook_t* hook,
                                    const hk_hook_spec_t* spec,
                                    const hk_hook_result_t* prepared) {
    void* original = hk_original_slot_load(hk_hook_original_slot(hook));
    if(!original && prepared) {
        original = (void*)prepared->continuation.address;
    }
    if(!original && spec && spec->target_kind == HK_TARGET_FUNCTION_SYMBOL &&
       spec->original_requirement == HK_ORIGINAL_DIRECT_PREDECESSOR) {
        original = dlsym(RTLD_DEFAULT, spec->target.symbol.name);
        if(original == spec->replacement) {
            original = NULL;
        }
    }
    return original;
}

static __thread void* gSHDWCurrentHookSession = NULL;

typedef struct {
    Method method;
    IMP original;
} SHDWOriginalIMP;

static SHDWOriginalIMP gSHDWOriginalIMPs[256];
static uint32_t gSHDWOriginalIMPCount;

// Hooked-method IMP remap registry. A detector reads the current IMP of a
// system method (class_getMethodImplementation) and dladdr()s it to see which
// image owns it; a hook moves that IMP into ShadowCore, betraying the hook
// (DeviceSecurityKit SwizzlingDetector.checkSystemMethodOrigins, ISS
// amIRuntimeHooked). Record replacement->original at hook time so replaced_dladdr
// can answer a query about a replacement IMP as though it were the original IMP,
// which still lives in the genuine system framework. Only entries whose original
// is a real (non-Shadow) image are useful; the dladdr path re-validates.
typedef struct {
    uintptr_t replacement;
    const void* original;
} SHDWHookedIMPRemap;

static SHDWHookedIMPRemap gSHDWHookedIMPRemaps[256];
static uint32_t gSHDWHookedIMPRemapCount;

void SHDWRememberHookedIMPRemap(const void* replacement, const void* original) {
    if(!replacement || !original || replacement == original) return;
    uint32_t count = __atomic_load_n(&gSHDWHookedIMPRemapCount, __ATOMIC_ACQUIRE);
    for(uint32_t i = 0; i < count; i++) {
        if(gSHDWHookedIMPRemaps[i].replacement == (uintptr_t)replacement) return;
    }
    if(count == sizeof(gSHDWHookedIMPRemaps) / sizeof(gSHDWHookedIMPRemaps[0])) return;
    gSHDWHookedIMPRemaps[count] = (SHDWHookedIMPRemap){ (uintptr_t)replacement, original };
    __atomic_store_n(&gSHDWHookedIMPRemapCount, count + 1, __ATOMIC_RELEASE);
}

// Snapshot an instance method's current IMP; pair with
// SHDWRegisterHookedInstanceMethod after the %hook installs to record the
// replacement->original mapping for the dladdr swizzle-origin filter.
void* SHDWSnapshotInstanceMethodIMP(Class cls, SEL sel) {
    if(!cls || !sel) return NULL;
    Method m = class_getInstanceMethod(cls, sel);
    return m ? (void*)method_getImplementation(m) : NULL;
}

void SHDWRegisterHookedInstanceMethod(Class cls, SEL sel, void* originalIMP) {
    if(!cls || !sel || !originalIMP) return;
    Method m = class_getInstanceMethod(cls, sel);
    if(!m) return;
    IMP hooked = method_getImplementation(m);
    if((void*)hooked != originalIMP) {
        SHDWRememberHookedIMPRemap((const void*)hooked, originalIMP);
        IMP viaClass = class_getMethodImplementation(cls, sel);
        if(viaClass && (void*)viaClass != originalIMP) {
            SHDWRememberHookedIMPRemap((const void*)viaClass, originalIMP);
        }
    }
}

const void* SHDWOriginalIMPForReplacement(const void* address) {
    if(!address) return NULL;
    uint32_t count = __atomic_load_n(&gSHDWHookedIMPRemapCount, __ATOMIC_ACQUIRE);
    for(uint32_t i = 0; i < count; i++) {
        if(gSHDWHookedIMPRemaps[i].replacement == (uintptr_t)address) {
            return gSHDWHookedIMPRemaps[i].original;
        }
    }
    return NULL;
}

// Process-global rebind journal. Count is the only mutated-scalar field and
// is published with release/acquire pairing (same discipline as the IMP
// remap tables above): writers append entries then bump the count, readers
// snapshot the count then touch only indices below it. Slot entries are
// never mutated in place except the expected-value refresh in
// shdw_rebind_slots_note, which the repair loop tolerates (worst case it
// stores a just-superseded value and the next event repairs again).
static shdw_rebind_slots_t gSHDWRebindSlots;

static void SHDWRememberImportSlot(uintptr_t start, size_t size, uintptr_t expected) {
    if(!start || !expected) return;
    if(!size) size = sizeof(void*);

    uint32_t overflowedBefore = __atomic_load_n(&gSHDWRebindSlots.overflowed, __ATOMIC_ACQUIRE);
    shdw_rebind_slots_note(&gSHDWRebindSlots, start, size, expected);
    // Publish for acquire-load readers (note() mutates the table in place;
    // installs are serialized on the coordinator queues, same as before).
    __atomic_store_n(&gSHDWRebindSlots.count, gSHDWRebindSlots.count, __ATOMIC_RELEASE);
    // Log the overflow transition once; every later drop stays silent but
    // latched in overflowed for the verify pass.
    if(!overflowedBefore && __atomic_load_n(&gSHDWRebindSlots.overflowed, __ATOMIC_ACQUIRE)) {
        NSLog(@"[Shadow] rebind journal full (%u slots) — further slots unguarded+unrepaired",
              __atomic_load_n(&gSHDWRebindSlots.count, __ATOMIC_ACQUIRE));
    }
}

static void SHDWRememberImportSlots(hk_report_t* report, uintptr_t fallbackExpected) {
    hk_artifact_snapshot_t* snapshot = NULL;
    if(!report || hk_report_copy_artifacts(report, &snapshot) != HK_STATUS_OK || !snapshot) return;

    size_t count = hk_artifact_snapshot_count(snapshot);
    for(size_t i = 0; i < count; i++) {
        hk_artifact_t artifact;
        if(hk_artifact_snapshot_copy_at(snapshot, i, &artifact) == HK_STATUS_OK &&
           hk_artifact_is_import_slot(&artifact)) {
            // Ground truth is what HookKit actually wrote; the spec's
            // replacement is only the fallback when the artifact omits it.
            uintptr_t expected = artifact.replacement_pointer
                ? (uintptr_t)artifact.replacement_pointer : fallbackExpected;
            SHDWRememberImportSlot(artifact.import_slot_address ?: artifact.address,
                                   artifact.size, expected);
        }
    }

    hk_artifact_snapshot_release(snapshot);
}

// Drop journaled slots owned by an unmapped image (see rebind_slots.h).
// Repair must never dereference a stale slot address.
void SHDWRebindForgetRange(uintptr_t base, uintptr_t end) {
    shdw_rebind_slots_forget_range(&gSHDWRebindSlots, base, end);
}

// Check-then-store repair over the journaled slots. Returns repaired count.
uint32_t SHDWRebindRepairSlots(void) {
    uint32_t count = __atomic_load_n(&gSHDWRebindSlots.count, __ATOMIC_ACQUIRE);
    uint32_t repaired = shdw_rebind_slots_repair(&gSHDWRebindSlots, count);
    if(repaired) {
        NSLog(@"[Shadow] rebind repair: restored %u import slots", repaired);
    }
    return repaired;
}

BOOL SHDWRangeOverlapsProtectedImportSlots(uintptr_t address, size_t size) {
    if(!address || !size) return NO;
    uint32_t count = __atomic_load_n(&gSHDWRebindSlots.count, __ATOMIC_ACQUIRE);
    return shdw_rebind_slots_overlap(&gSHDWRebindSlots, count, address, size) ? YES : NO;
}

static void SHDWRememberOriginalImplementation(Method method, IMP original) {
    if(!method || !original) return;

    uint32_t count = __atomic_load_n(&gSHDWOriginalIMPCount, __ATOMIC_ACQUIRE);
    for(uint32_t i = 0; i < count; i++) {
        if(gSHDWOriginalIMPs[i].method == method) return;
    }
    if(count == sizeof(gSHDWOriginalIMPs) / sizeof(gSHDWOriginalIMPs[0])) return;

    gSHDWOriginalIMPs[count] = (SHDWOriginalIMP){ method, original };
    __atomic_store_n(&gSHDWOriginalIMPCount, count + 1, __ATOMIC_RELEASE);
}

IMP SHDWOriginalImplementationForMethod(Method method) {
    uint32_t count = __atomic_load_n(&gSHDWOriginalIMPCount, __ATOMIC_ACQUIRE);
    for(uint32_t i = 0; i < count; i++) {
        if(gSHDWOriginalIMPs[i].method == method) return gSHDWOriginalIMPs[i].original;
    }
    return NULL;
}

SHDWHookSession* SHDWHookSessionSetCurrent(SHDWHookSession* session) {
    SHDWHookSession* previous = (__bridge SHDWHookSession*)gSHDWCurrentHookSession;
    gSHDWCurrentHookSession = (__bridge void*)session;
    return previous;
}

void SHDWHookMessage(Class objcClass, SEL selector, IMP replacement,
                     IMP* original) {
    SHDWHookSession* session = (__bridge SHDWHookSession*)gSHDWCurrentHookSession;
    if(session) {
        [session hookMessageInClass:objcClass
                        withSelector:selector
                     withReplacement:(void*)replacement
                            outOldPtr:(void**)original];
    }
}

static BOOL shdw_apply_hook_spec_once(
    const hk_hook_spec_t* spec, void** oldPtr, const char* backendOverride,
    SHDWHKRuntimeCreateWithBackendOverride createWithOverride,
    BOOL* outCleanRefusal) {
    if(outCleanRefusal) {
        *outCleanRefusal = NO;
    }

    // Snapshot whether the cell already holds a continuation this session
    // published: a live replacement may chain through it, so failures must
    // preserve it. Any other input is neutralized up front so every early
    // exit below (including creation failures) is safe.
    void* entryOriginal = oldPtr ? *oldPtr : NULL;
    BOOL entryPublished = entryOriginal && shdw_cell_holds_published_original(oldPtr);
    if(oldPtr && !entryPublished) {
        *oldPtr = NULL;
    }

    hk_runtime_config_t config;
    memset(&config, 0, sizeof(config));
    config.struct_size = sizeof(config);
    config.struct_version = HK_ABI_VERSION_3_0;
    config.install_context = HK_INSTALL_CONTEXT_EARLY_PROCESS;

    hk_runtime_t* runtime = NULL;
    hk_plan_t* plan = NULL;
    hk_hook_t* hook = NULL;
    hk_report_t* commitReport = NULL;
    BOOL installed = NO;

    hk_status_t runtimeStatus =
        backendOverride
            ? createWithOverride(&config, backendOverride, &runtime)
            : hk_runtime_create(&config, &runtime);

    if(runtimeStatus != HK_STATUS_OK || !runtime ||
       hk_plan_create(runtime, NULL, &plan) != HK_STATUS_OK || !plan ||
       hk_plan_add_hook(plan, spec, &hook) != HK_STATUS_OK || !hook) {
        goto done;
    }

    if(hk_plan_analyze(plan, NULL) != HK_STATUS_OK) {
        shdw_finish_uninstalled_hook(hook, oldPtr, entryPublished, outCleanRefusal);
        goto done;
    }

    hk_hook_result_t prepared;
    if(hk_hook_copy_result(hook, &prepared) != HK_STATUS_OK ||
       prepared.outcome != HK_OUTCOME_ANALYZED) {
        shdw_finish_uninstalled_hook(hook, oldPtr, entryPublished, outCleanRefusal);
        goto done;
    }

    if(hk_plan_prepare(plan, NULL) != HK_STATUS_OK) {
        shdw_finish_uninstalled_hook(hook, oldPtr, entryPublished, outCleanRefusal);
        goto done;
    }

    if(hk_hook_copy_result(hook, &prepared) != HK_STATUS_OK ||
       prepared.outcome != HK_OUTCOME_PREPARED) {
        shdw_finish_uninstalled_hook(hook, oldPtr, entryPublished, outCleanRefusal);
        goto done;
    }

    if(oldPtr) {
        void* preparedOriginal = shdw_prepared_original(hook, spec, &prepared);
        if(!preparedOriginal && spec->original_requirement != HK_ORIGINAL_NONE) {
            goto done;
        }
        if(preparedOriginal) {
            *oldPtr = preparedOriginal;
            shdw_note_published_cell(oldPtr);
        }
    }

    if(hk_plan_commit(plan, &commitReport) != HK_STATUS_OK) {
        shdw_finish_uninstalled_hook(hook, oldPtr, entryPublished, outCleanRefusal);
        goto done;
    }

    hk_hook_result_t result;
    hk_status_t resultStatus = hk_hook_copy_result(hook, &result);
    if(resultStatus != HK_STATUS_OK || result.outcome != HK_OUTCOME_ACTIVE) {
        if(resultStatus == HK_STATUS_OK) {
            shdw_finish_uninstalled_hook(hook, oldPtr, entryPublished, outCleanRefusal);
        }
        goto done;
    }
    if(spec->target_kind == HK_TARGET_FUNCTION_SYMBOL &&
       (spec->required_reach & HK_REACH_EXISTING_IMPORTS)) {
        SHDWRememberImportSlots(commitReport, (uintptr_t)spec->replacement);
    }
    if(oldPtr) {
        void* original = hk_original_slot_load(hk_hook_original_slot(hook));
        if(!result.original_available || !original) {
            goto done;
        }
        *oldPtr = original;
        shdw_note_published_cell(oldPtr);
    }
    installed = YES;

done:
    hk_report_release(commitReport);
    hk_plan_release(plan);
    hk_runtime_release(runtime);
    return installed;
}

static BOOL shdw_apply_hook_spec(const hk_hook_spec_t* spec, void** oldPtr) {
    // An override is strict for its first attempt. A clean refusal proves that
    // no target changed, so Shadow may retry normal automatic routing once.
    SHDWHKRuntimeCreateWithBackendOverride createWithOverride =
        (SHDWHKRuntimeCreateWithBackendOverride)dlsym(
            RTLD_DEFAULT, "hk_runtime_create_with_backend_override");
    const char* backendOverride = gSHDWBackendOverride[0] && createWithOverride
        ? gSHDWBackendOverride : NULL;
    BOOL cleanRefusal = NO;
    // Commit can enter a newly rebound replacement; publish its continuation
    // into caller storage before the first mutation.
    BOOL installed = shdw_apply_hook_spec_once(
        spec, oldPtr, backendOverride, createWithOverride, &cleanRefusal);

    if(!installed && backendOverride && cleanRefusal &&
       spec->target_kind != HK_TARGET_OBJC_METHOD) {
        installed = shdw_apply_hook_spec_once(
            spec, oldPtr, NULL, createWithOverride, NULL);
    }
    return installed;
}

static void shdw_init_spec(hk_hook_spec_t* spec, const char* stableID,
                           hk_target_kind_t kind, void* replacement,
                           hk_reachability_t reach,
                           hk_original_requirement_t originalRequirement) {
    memset(spec, 0, sizeof(*spec));
    spec->struct_size = sizeof(*spec);
    spec->struct_version = HK_ABI_VERSION_3_0;
    spec->stable_hook_id = stableID;
    spec->target_kind = kind;
    spec->replacement = replacement;
    spec->required_reach = reach;
    spec->preferred_reach = reach;
    spec->original_requirement = originalRequirement;
    spec->continuation_policy = HK_CONTINUATION_ANY;
    spec->availability = HK_AVAILABILITY_REQUIRED_NOW;
    spec->role = HK_OPERATION_MANDATORY;
}

@implementation SHDWHookSession {
    dispatch_queue_t _lifecycleQueue;
    NSMutableArray* _pendingTargets;
    BOOL _drainingTargets;
}

- (instancetype)init {
    return [self initWithLifecycleQueue:dispatch_queue_create("com.shadow.hooksession.lifecycle", DISPATCH_QUEUE_SERIAL)];
}

- (instancetype)initWithLifecycleQueue:(dispatch_queue_t)queue {
    NSParameterAssert(queue);
    self = [super init];
    if(self) {
        _lifecycleQueue = queue;
        dispatch_queue_set_specific(queue, (__bridge const void*)self, (__bridge void*)self, NULL);
        _pendingTargets = [NSMutableArray new];
    }
    return self;
}

- (void)dealloc {
    if(_lifecycleQueue) dispatch_queue_set_specific(_lifecycleQueue, (__bridge const void*)self, NULL, NULL);
}

- (BOOL)performWhenTargetAvailable:(BOOL (^)(SHDWHookSession*))attempt {
    if(!attempt) return YES;
    __block BOOL completed = NO;
    __block NSException* failure = nil;
    void (^work)(void) = ^{
        @try {
            completed = attempt(self);
            if(!completed) [_pendingTargets addObject:[attempt copy]];
        } @catch(NSException* exception) {
            failure = exception;
        }
    };
    if(dispatch_get_specific((__bridge const void*)self)) work();
    else dispatch_sync(_lifecycleQueue, work);
    if(failure) @throw failure;
    return completed;
}

- (void)drainPendingTargets {
    __block NSException* failure = nil;
    void (^work)(void) = ^{
        if(_drainingTargets) return;
        _drainingTargets = YES;
        @try {
            for(BOOL (^attempt)(SHDWHookSession*) in [_pendingTargets copy]) {
                // Remove before invoking: exceptions are terminal and new
                // registrations cannot mutate the snapshot being enumerated.
                [_pendingTargets removeObjectIdenticalTo:attempt];
                @try {
                    if(!attempt(self)) [_pendingTargets addObject:attempt];
                } @catch(NSException* exception) {
                    if(!failure) failure = exception;
                }
            }
        } @catch(NSException* exception) {
            if(!failure) failure = exception;
        } @finally {
            _drainingTargets = NO;
        }
    };
    if(dispatch_get_specific((__bridge const void*)self)) work();
    else dispatch_sync(_lifecycleQueue, work);
    if(failure) @throw failure;
}

- (BOOL)hookMessageInClass:(Class)objcClass
              withSelector:(SEL)selector
           withReplacement:(void*)replacement
                  outOldPtr:(void**)oldPtr {
    if(!objcClass || !selector || !replacement) {
        shdw_clear_unpublished_cell(oldPtr);
        return NO;
    }

    // Keep the established ambiguous-selector behavior: an instance method
    // wins; otherwise install against the class metaclass.
    Class dispatchClass = class_getInstanceMethod(objcClass, selector)
        ? objcClass : object_getClass(objcClass);
    Method methodBefore = class_getInstanceMethod(dispatchClass, selector);
    hk_hook_spec_t spec;
    shdw_init_spec(&spec, "shadow.objc", HK_TARGET_OBJC_METHOD, replacement,
                   HK_REACH_OBJC_DISPATCH, oldPtr
                       ? HK_ORIGINAL_DIRECT_PREDECESSOR : HK_ORIGINAL_NONE);
    spec.target.objc = hk_objc_instance_method(dispatchClass, selector);
    hk_objc_target_allow_inherited(&spec.target.objc);
    spec.target.objc.availability = HK_AVAILABILITY_REQUIRED_NOW;
    BOOL installed = shdw_apply_hook_spec(&spec, oldPtr);
    if(installed && oldPtr && *oldPtr) {
        SHDWRememberOriginalImplementation(methodBefore, (IMP)*oldPtr);
        SHDWRememberOriginalImplementation(
            class_getInstanceMethod(dispatchClass, selector), (IMP)*oldPtr);

        // dladdr remap: a detector that reads the method's post-hook IMP and
        // dladdr()s it must resolve to the original system image, not
        // ShadowCore. Record both the replacement pointer and the method's
        // actual current IMP (the engine may publish a trampoline rather than
        // the raw replacement) against the original continuation.
        SHDWRememberHookedIMPRemap(replacement, *oldPtr);
        Method methodAfter = class_getInstanceMethod(dispatchClass, selector);
        if(methodAfter) {
            SHDWRememberHookedIMPRemap((const void*)method_getImplementation(methodAfter), *oldPtr);
        }
        // class_getMethodImplementation may return a different pointer than
        // method_getImplementation (dispatch trampoline); record it too so a
        // dladdr on either resolves to the original.
        IMP viaClass = class_getMethodImplementation(dispatchClass, selector);
        if(viaClass) {
            SHDWRememberHookedIMPRemap((const void*)viaClass, *oldPtr);
        }
    }
    return installed;
}

- (BOOL)hookFunction:(void*)function
      withReplacement:(void*)replacement
             outOldPtr:(void**)oldPtr {
    if(!function || !replacement) {
        shdw_clear_unpublished_cell(oldPtr);
        return NO;
    }

    hk_hook_spec_t spec;
    shdw_init_spec(&spec, "shadow.function", HK_TARGET_FUNCTION_ADDRESS,
                   replacement, HK_REACH_ENTRYPOINT, oldPtr
                       ? HK_ORIGINAL_CALLABLE_CONTINUATION : HK_ORIGINAL_NONE);
    spec.target.address.struct_size = sizeof(spec.target.address);
    spec.target.address.struct_version = HK_ABI_VERSION_3_0;
    spec.target.address.address = (uintptr_t)function;
    BOOL installed = shdw_apply_hook_spec(&spec, oldPtr);

    // dladdr remap: a detector that resolves a hooked C function (via
    // dlsym, which returns the replacement for GOT/dlsym agreement) and
    // dladdr()s it must see the original's system image, not ShadowCore
    // (DeviceSecurityKit HookDetector.checkSystemFunctionOrigins). Map the
    // replacement to the pre-hook function address; replaced_dladdr resolves
    // the query against it when the original is a genuine (non-Shadow) image.
    if(installed) {
        SHDWRememberHookedIMPRemap(replacement, function);
    }
    return installed;
}

- (BOOL)hookRebindSymbol:(NSString*)symbolName
          withReplacement:(void*)replacement
                 outOldPtr:(void**)oldPtr {
    return [self hookRebindSymbol:symbolName
                  withReplacement:replacement
                         outOldPtr:oldPtr
                     inCallerImage:NULL];
}

- (BOOL)hookRebindSymbol:(NSString*)symbolName
           withReplacement:(void*)replacement
                  outOldPtr:(void**)oldPtr
              inCallerImage:(const void*)imageHeader {
    return [self hookRebindSymbol:symbolName
                  withReplacement:replacement
                         outOldPtr:oldPtr
                     inCallerImage:imageHeader
                           journal:YES];
}

- (BOOL)hookRebindSymbol:(NSString*)symbolName
           withReplacement:(void*)replacement
                  outOldPtr:(void**)oldPtr
              inCallerImage:(const void*)imageHeader
                    journal:(BOOL)journal {
    if(!symbolName.length || !replacement) {
        shdw_clear_unpublished_cell(oldPtr);
        return NO;
    }

    if(journal) {
        SHDWRebindJournalNote(symbolName.UTF8String, replacement);
    }

    hk_hook_spec_t spec;
    shdw_init_spec(&spec, "shadow.rebind", HK_TARGET_FUNCTION_SYMBOL,
                    replacement, HK_REACH_EXISTING_IMPORTS, oldPtr
                        ? HK_ORIGINAL_DIRECT_PREDECESSOR : HK_ORIGINAL_NONE);
    spec.target.symbol.struct_size = sizeof(spec.target.symbol);
    spec.target.symbol.struct_version = HK_ABI_VERSION_3_0;
    spec.target.symbol.name = symbolName.UTF8String;
    spec.target.symbol.name_convention = [symbolName hasPrefix:@"$s"]
        ? HK_SYMBOL_NAME_SWIFT_MANGLED : HK_SYMBOL_NAME_C;
    spec.target.symbol.defining_image.struct_size = sizeof(spec.target.symbol.defining_image);
    spec.target.symbol.defining_image.struct_version = HK_ABI_VERSION_3_0;
    spec.target.symbol.defining_image.kind = HK_IMAGE_ANY_LOADED;
    spec.target.symbol.caller_image_scope.struct_size = sizeof(spec.target.symbol.caller_image_scope);
    spec.target.symbol.caller_image_scope.struct_version = HK_ABI_VERSION_3_0;
    spec.target.symbol.caller_image_scope.kind = imageHeader
        ? HK_IMAGE_EXACT_HEADER : HK_IMAGE_ANY_LOADED;
    spec.target.symbol.caller_image_scope.header = imageHeader;
    spec.target.symbol.alias_policy = HK_SYMBOL_ALIAS_EXACT_ONLY;
    return shdw_apply_hook_spec(&spec, oldPtr);
}

- (SHDWImageRef)openImage:(NSString*)path {
    return path.length ? [path copy] : nil;
}

- (void)closeImage:(SHDWImageRef)image {
    (void)image;
}

- (void*)findSymbolInImage:(SHDWImageRef)image symbolName:(NSString*)symbolName {
    if(!symbolName.length) {
        return NULL;
    }

    hk_runtime_t* runtime = NULL;
    void* address = NULL;
    if(hk_runtime_create(NULL, &runtime) == HK_STATUS_OK && runtime) {
        (void)hk_runtime_find_symbol(runtime, image.fileSystemRepresentation,
                                     symbolName.UTF8String, &address);
    }
    hk_runtime_release(runtime);
    return address;
}

@end
