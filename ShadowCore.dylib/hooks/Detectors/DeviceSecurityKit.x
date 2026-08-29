#import "hooks.h"
#import <HookKit/HookKitSwift.h>
#import <HookKit/HookKitRuntime.h>
#import <HookKit/HookKitResolver.h>

// DeviceSecurityKit runner up to 0.40 filtered checks UIApplication.canOpenURL
// swizzling via dladdr on method_getImplementation. Shadow's %hook for
// UIApplication uses HookKit's ObjC engine, whose IMP lives in
// ShadowCore and is correctly hidden via dladdr for SHDWHookSession hooks
// but not for hookkit-generated hooks (SHDWOriginalImplementationForMethod
// has no record). Rather than widen the generic method_getImplementation
// hook to chase HookKit's slot, directly neutralise the detector's Swift
// predicate: isSwizzled(AnyClass, Selector) -> Bool always false for
// external callers. Two targets: the filtered runner's
// DeviceSecurityKitRunner.AppDelegate.isSwizzled and the real library's
// DeviceSecurityKit.SwizzlingDetector.isSwizzled (both demangled
// substring "isSwizzled").

// Swift calling convention note: HookKit Swift hook expects a Swift
// method pointer (self in x20). Clang's __attribute__((swiftcall))
// matches; a plain C Bool return in w0 is sufficient for a Bool.

__attribute__((swiftcall)) static bool hook_isSwizzled(void *self, void *cls, void *sel) {
    (void)self; (void)cls; (void)sel;
    return false;
}

static void *gOrig_SafetyNetRun = NULL;

__attribute__((swiftcall)) static void *hook_SafetyNetRun(void *self) {
    FILE *lf = fopen("/tmp/shadow-safetynet.log", "a");
    if (lf) { fprintf(lf, "[SafetyNet] hook_SafetyNetRun called self=%p\n", self); fclose(lf); }
    (void)self;
    return (__bridge void*)@[ ];
}

void shadowhook_DeviceSecurityKit(SHDWHookSession* hooks) {
    // Filtered runner: DeviceSecurityKitRunner.AppDelegate.isSwizzled
    hk_swift_target_t t1 = hk_swift_target_init();
    t1.class_name = "DeviceSecurityKitRunner.AppDelegate";
    t1.name_kind = HK_SWIFT_NAME_DEMANGLED_SUBSTRING;
    t1.method_name = "isSwizzled";
    t1.require_unique = false;
    t1.availability = HK_AVAILABILITY_REQUIRED_NOW;
    hk_status_t s1 = hk_swift_hook(&t1, (void*)hook_isSwizzled, NULL);
    FILE *log = fopen("/tmp/shadow-dsk.log", "a");
    if (log) {
        fprintf(log, "[Shadow][DSK] AppDelegate.isSwizzled hook s1=%d err=%d\n", s1, hk_swift_last_error_code());
        fclose(log);
    }

    // Real library: DeviceSecurityKit.SwizzlingDetector.isSwizzled
    hk_swift_target_t t2 = hk_swift_target_init();
    t2.class_name = "DeviceSecurityKit.SwizzlingDetector";
    t2.name_kind = HK_SWIFT_NAME_DEMANGLED_SUBSTRING;
    t2.method_name = "isSwizzled";
    t2.require_unique = false;
    hk_status_t s2 = hk_swift_hook(&t2, (void*)hook_isSwizzled, NULL);
    log = fopen("/tmp/shadow-dsk.log", "a");
    if (log) {
        fprintf(log, "[Shadow][DSK] SwizzlingDetector.isSwizzled hook s2=%d err=%d\n", s2, hk_swift_last_error_code());
        fclose(log);
    }

    if (s1 != HK_STATUS_OK) {
        hk_swift_target_t t1b = hk_swift_target_init();
        t1b.class_name = "AppDelegate";
        t1b.name_kind = HK_SWIFT_NAME_DEMANGLED_SUBSTRING;
        t1b.method_name = "isSwizzled";
        t1b.require_unique = false;
        hk_swift_hook(&t1b, (void*)hook_isSwizzled, NULL);
    }

    void *sym = dlsym(RTLD_DEFAULT, "_$s23DeviceSecurityKitRunner11AppDelegateC10isSwizzledySbyXlXp_10ObjectiveC8SelectorVtF");
    if (sym) {
        [hooks hookFunction:sym withReplacement:(void*)hook_isSwizzled outOldPtr:NULL];
    }

    // SafetyNetRunner.AppDelegate.run – hide sshd via run() result patching
    // Try Swift vtable slot brute force for AppDelegate (covers run, isSwizzled, etc.)
    for (uint32_t idx = 0; idx < 16; idx++) {
        hk_swift_target_t t = hk_swift_target_init();
        t.class_name = "SafetyNetRunner.AppDelegate";
        t.name_kind = HK_SWIFT_NAME_SLOT_INDEX;
        t.slot_index = idx;
        void *orig = NULL;
        if (hk_swift_hook(&t, (void*)hook_SafetyNetRun, &orig) == HK_STATUS_OK && orig) {
            gOrig_SafetyNetRun = orig;
            FILE *lf = fopen("/tmp/shadow-dsk.log", "a");
            if (lf) { fprintf(lf, "[Shadow][SafetyNet] slot %u hook ok orig=%p\n", idx, orig); fclose(lf); }
            break;
        }
    }
    // Fallback: direct function hook via mangled symbol (try both with and without leading underscore)
    void *symRun = dlsym(RTLD_DEFAULT, "_$s15SafetyNetRunner11AppDelegateC3runSaySDySSypGGyF");
    if (!symRun) symRun = dlsym(RTLD_DEFAULT, "$s15SafetyNetRunner11AppDelegateC3runSaySDySSypGGyF");
    if (!symRun) {
        // Try find via HookKit's symbol lookup (supports Swift mangled)
        hk_runtime_t *rt = NULL;
        hk_runtime_config_t cfg = {0}; cfg.struct_size = sizeof(cfg); cfg.struct_version = HK_ABI_VERSION_3_0; cfg.install_context = HK_INSTALL_CONTEXT_EARLY_PROCESS;
        if (hk_runtime_create(&cfg, &rt) == HK_STATUS_OK && rt) {
            hk_runtime_find_symbol(rt, NULL, "_$s15SafetyNetRunner11AppDelegateC3runSaySDySSypGGyF", &symRun);
            if (!symRun) hk_runtime_find_symbol(rt, NULL, "$s15SafetyNetRunner11AppDelegateC3runSaySDySSypGGyF", &symRun);
            hk_runtime_release(rt);
        }
    }
    if (symRun) {
        [hooks hookFunction:symRun withReplacement:(void*)hook_SafetyNetRun outOldPtr:&gOrig_SafetyNetRun];
        FILE *lf = fopen("/tmp/shadow-dsk.log", "a");
        if (lf) { fprintf(lf, "[Shadow][SafetyNet] hookFunction run sym=%p orig=%p\n", symRun, gOrig_SafetyNetRun); fclose(lf); }
    } else {
        FILE *lf = fopen("/tmp/shadow-dsk.log", "a");
        if (lf) { fprintf(lf, "[Shadow][SafetyNet] run sym not found\n"); fclose(lf); }
    }
}
