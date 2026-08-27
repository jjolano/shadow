#import "SHDWHookSession.h"

#import <HookKit/HookKit.h>
#import <HookKit/HookKitObjC.h>
#import <HookKit/HookKitResolver.h>

#include <string.h>

static __thread void* gSHDWCurrentHookSession = NULL;

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

static BOOL shdw_apply_hook_spec(const hk_hook_spec_t* spec, void** oldPtr) {
    if(oldPtr) {
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
    BOOL installed = NO;

    if(hk_runtime_create(&config, &runtime) != HK_STATUS_OK || !runtime ||
       hk_plan_create(runtime, NULL, &plan) != HK_STATUS_OK || !plan ||
       hk_plan_add_hook(plan, spec, &hook) != HK_STATUS_OK || !hook ||
       hk_plan_analyze(plan, NULL) != HK_STATUS_OK ||
       hk_plan_prepare(plan, NULL) != HK_STATUS_OK) {
        goto done;
    }

    if(oldPtr) {
        hk_hook_result_t prepared;
        if(hk_hook_copy_result(hook, &prepared) != HK_STATUS_OK ||
           prepared.outcome != HK_OUTCOME_PREPARED) {
            goto done;
        }
        // ObjC and relocating engines may publish before mutation; provider
        // engines publish through their HK3 original slot at commit.
        if(prepared.continuation.address) {
            *oldPtr = (void*)prepared.continuation.address;
        }
    }

    if(hk_plan_commit(plan, NULL) != HK_STATUS_OK) {
        if(oldPtr) {
            *oldPtr = NULL;
        }
        goto done;
    }

    hk_hook_result_t result;
    if(hk_hook_copy_result(hook, &result) != HK_STATUS_OK ||
       result.outcome != HK_OUTCOME_ACTIVE) {
        if(oldPtr) {
            *oldPtr = NULL;
        }
        goto done;
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
    hk_plan_release(plan);
    hk_runtime_release(runtime);
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
    hk_hook_spec_t spec;
    shdw_init_spec(&spec, "shadow.objc", HK_TARGET_OBJC_METHOD, replacement,
                   HK_REACH_OBJC_DISPATCH, oldPtr
                       ? HK_ORIGINAL_DIRECT_PREDECESSOR : HK_ORIGINAL_NONE);
    spec.target.objc = hk_objc_instance_method(dispatchClass, selector);
    spec.target.objc.inheritance_policy = HK_OBJC_ALLOW_INHERITED_OVERRIDE;
    spec.target.objc.availability = HK_AVAILABILITY_REQUIRED_NOW;
    return shdw_apply_hook_spec(&spec, oldPtr);
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
