#import "SHDWHookSession.h"
#import "SHDWHookFallback.h"

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

static BOOL shdw_hook_refused_cleanly(hk_hook_t* hook) {
    hk_hook_result_t result;
    return hook && hk_hook_copy_result(hook, &result) == HK_STATUS_OK &&
        shdw_hook_result_refused_cleanly(&result);
}

static __thread void* gSHDWCurrentHookSession = NULL;

typedef struct {
    Method method;
    IMP original;
} SHDWOriginalIMP;

static SHDWOriginalIMP gSHDWOriginalIMPs[256];
static uint32_t gSHDWOriginalIMPCount;

typedef struct {
    uintptr_t start;
    uintptr_t end;
} SHDWImportSlotRange;

static SHDWImportSlotRange gSHDWImportSlots[2048];
static uint32_t gSHDWImportSlotCount;

static void SHDWRememberImportSlot(uintptr_t start, size_t size) {
    if(!start) return;
    if(!size) size = sizeof(void*);

    uintptr_t end = size > UINTPTR_MAX - start ? UINTPTR_MAX : start + size;
    uint32_t count = __atomic_load_n(&gSHDWImportSlotCount, __ATOMIC_ACQUIRE);
    for(uint32_t i = 0; i < count; i++) {
        if(gSHDWImportSlots[i].start == start && gSHDWImportSlots[i].end == end) return;
    }
    if(count == sizeof(gSHDWImportSlots) / sizeof(gSHDWImportSlots[0])) return;

    gSHDWImportSlots[count] = (SHDWImportSlotRange){ start, end };
    __atomic_store_n(&gSHDWImportSlotCount, count + 1, __ATOMIC_RELEASE);
}

static void SHDWRememberImportSlots(hk_report_t* report) {
    hk_artifact_snapshot_t* snapshot = NULL;
    if(!report || hk_report_copy_artifacts(report, &snapshot) != HK_STATUS_OK || !snapshot) return;

    size_t count = hk_artifact_snapshot_count(snapshot);
    for(size_t i = 0; i < count; i++) {
        hk_artifact_t artifact;
        if(hk_artifact_snapshot_copy_at(snapshot, i, &artifact) == HK_STATUS_OK &&
           hk_artifact_is_import_slot(&artifact)) {
            SHDWRememberImportSlot(artifact.import_slot_address ?: artifact.address,
                                   artifact.size);
        }
    }

    hk_artifact_snapshot_release(snapshot);
}

BOOL SHDWRangeOverlapsProtectedImportSlots(uintptr_t address, size_t size) {
    if(!address || !size) return NO;
    uintptr_t end = size > UINTPTR_MAX - address ? UINTPTR_MAX : address + size;
    uint32_t count = __atomic_load_n(&gSHDWImportSlotCount, __ATOMIC_ACQUIRE);
    for(uint32_t i = 0; i < count; i++) {
        if(address < gSHDWImportSlots[i].end && end > gSHDWImportSlots[i].start) return YES;
    }
    return NO;
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
    if(oldPtr) {
        *oldPtr = NULL;
    }
    if(outCleanRefusal) {
        *outCleanRefusal = NO;
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
        if(outCleanRefusal) {
            *outCleanRefusal = shdw_hook_refused_cleanly(hook);
        }
        goto done;
    }

    hk_hook_result_t prepared;
    if(hk_hook_copy_result(hook, &prepared) != HK_STATUS_OK ||
       prepared.outcome != HK_OUTCOME_ANALYZED) {
        if(outCleanRefusal) {
            *outCleanRefusal = shdw_hook_refused_cleanly(hook);
        }
        goto done;
    }

    if(hk_plan_prepare(plan, NULL) != HK_STATUS_OK) {
        if(outCleanRefusal) {
            *outCleanRefusal = shdw_hook_refused_cleanly(hook);
        }
        goto done;
    }

    if(hk_hook_copy_result(hook, &prepared) != HK_STATUS_OK ||
       prepared.outcome != HK_OUTCOME_PREPARED) {
        if(outCleanRefusal) {
            *outCleanRefusal = shdw_hook_refused_cleanly(hook);
        }
        goto done;
    }

    if(oldPtr) {
        // ObjC and relocating engines may publish before mutation; provider
        // engines publish through their HK3 original slot at commit.
        if(prepared.continuation.address) {
            *oldPtr = (void*)prepared.continuation.address;
        }
    }

    if(hk_plan_commit(plan, &commitReport) != HK_STATUS_OK) {
        if(oldPtr) {
            *oldPtr = NULL;
        }
        if(outCleanRefusal) {
            *outCleanRefusal = shdw_hook_refused_cleanly(hook);
        }
        goto done;
    }

    hk_hook_result_t result;
    if(hk_hook_copy_result(hook, &result) != HK_STATUS_OK ||
       result.outcome != HK_OUTCOME_ACTIVE) {
        if(oldPtr) {
            *oldPtr = NULL;
        }
        if(outCleanRefusal) {
            *outCleanRefusal = shdw_hook_refused_cleanly(hook);
        }
        goto done;
    }
    if(spec->target_kind == HK_TARGET_FUNCTION_SYMBOL &&
       (spec->required_reach & HK_REACH_EXISTING_IMPORTS)) {
        SHDWRememberImportSlots(commitReport);
    }
    if(oldPtr) {
        void* original = hk_original_slot_load(hk_hook_original_slot(hook));
        if(!result.original_available || !original) {
            *oldPtr = NULL;
            goto done;
        }
        *oldPtr = original;
    }
    installed = YES;

done:
    hk_report_release(commitReport);
    hk_plan_release(plan);
    hk_runtime_release(runtime);
    return installed;
}

static BOOL shdw_apply_hook_spec(const hk_hook_spec_t* spec, void** oldPtr) {
    if(oldPtr) {
        *oldPtr = NULL;
    }

    // An override is strict for its first attempt. A clean refusal proves that
    // no target changed, so Shadow may retry normal automatic routing once.
    SHDWHKRuntimeCreateWithBackendOverride createWithOverride =
        (SHDWHKRuntimeCreateWithBackendOverride)dlsym(
            RTLD_DEFAULT, "hk_runtime_create_with_backend_override");
    const char* backendOverride = gSHDWBackendOverride[0] && createWithOverride
        ? gSHDWBackendOverride : NULL;
    BOOL cleanRefusal = NO;
    void* original = NULL;
    void** attemptOldPtr = oldPtr ? &original : NULL;
    BOOL installed = shdw_apply_hook_spec_once(
        spec, attemptOldPtr, backendOverride, createWithOverride, &cleanRefusal);

    if(!installed && backendOverride && cleanRefusal &&
       spec->target_kind != HK_TARGET_OBJC_METHOD) {
        installed = shdw_apply_hook_spec_once(
            spec, attemptOldPtr, NULL, createWithOverride, NULL);
    }
    if(oldPtr) {
        *oldPtr = original;
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

@implementation SHDWHookSession

- (BOOL)hookMessageInClass:(Class)objcClass
              withSelector:(SEL)selector
           withReplacement:(void*)replacement
                  outOldPtr:(void**)oldPtr {
    if(!objcClass || !selector || !replacement) {
        if(oldPtr) {
            *oldPtr = NULL;
        }
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
    }
    return installed;
}

- (BOOL)hookFunction:(void*)function
      withReplacement:(void*)replacement
             outOldPtr:(void**)oldPtr {
    if(!function || !replacement) {
        if(oldPtr) {
            *oldPtr = NULL;
        }
        return NO;
    }

    hk_hook_spec_t spec;
    shdw_init_spec(&spec, "shadow.function", HK_TARGET_FUNCTION_ADDRESS,
                   replacement, HK_REACH_ENTRYPOINT, oldPtr
                       ? HK_ORIGINAL_CALLABLE_CONTINUATION : HK_ORIGINAL_NONE);
    spec.target.address.struct_size = sizeof(spec.target.address);
    spec.target.address.struct_version = HK_ABI_VERSION_3_0;
    spec.target.address.address = (uintptr_t)function;
    return shdw_apply_hook_spec(&spec, oldPtr);
}

- (BOOL)hookRebindSymbol:(NSString*)symbolName
          withReplacement:(void*)replacement
                 outOldPtr:(void**)oldPtr {
    if(!symbolName.length || !replacement) {
        if(oldPtr) {
            *oldPtr = NULL;
        }
        return NO;
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
    spec.target.symbol.caller_image_scope.kind = HK_IMAGE_ANY_LOADED;
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
