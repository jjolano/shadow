#import "UniversalHooks.h"

// Captured in shadowhook_objc (see below); declared here so the
// class-hiding helpers above it can resolve a class's image path.
static const char* (*original_class_getImageName)(Class cls);

// --- Main-executable exemption (host app classes are never hidden) ----------
// The class/method/IMP lookups below hide anything whose containing image is
// restricted. The HOST APP's own executable is never a hiding target: hiding
// its classes breaks the app itself — UIKit's _UIApplicationMainPreparations
// resolves the app delegate via NSClassFromString, and rootless jailbreak
// apps are installed under /private/preboot, which isCPathRestricted: treats
// as restricted (observed on-device: ShadowHarness aborted with "No class
// named AppDelegate is loaded" the moment hooks installed). Exempt the main
// executable BEFORE any range verdict; canonical Shadow package images remain
// hidden via the own-ranges check, while the broader protected-image policy
// handles third-party jailbreak artifacts.

// Cached span of the main executable (dyld image 0), built once at first use.
static BOOL shdw_addr_in_main_image(const void* addr) {
    if(!addr) {
        return NO;
    }

    static uintptr_t mainBase = 0;
    static uintptr_t mainEnd = 0;
    static dispatch_once_t once = 0;

    dispatch_once(&once, ^{
        const struct mach_header* mh = _dyld_get_image_header(0);
        intptr_t slide = _dyld_get_image_vmaddr_slide(0);

        if(!mh) {
            return;
        }

        // Walk segment load commands once: the image's resident span is
        // [min(vmaddr), max(vmaddr+vmsize)) + slide.
        const struct load_command* lc = (const struct load_command *)((const char *)mh + sizeof(struct mach_header_64));
        uintptr_t lo = (uintptr_t)-1;
        uintptr_t hi = 0;

        for(uint32_t i = 0; i < mh->ncmds; i++) {
            if(lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64* seg = (const struct segment_command_64 *)lc;
                uintptr_t base = (uintptr_t)(seg->vmaddr + slide);
                uintptr_t end = base + seg->vmsize;

                if(base < lo) {
                    lo = base;
                }

                if(end > hi) {
                    hi = end;
                }
            }

            lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
        }

        if(hi > lo) {
            mainBase = lo;
            mainEnd = hi;
        }
    });

    if(mainEnd == 0) {
        return NO;
    }

    uintptr_t a = (uintptr_t)addr;
    return a >= mainBase && a < mainEnd;
}

// Hiding predicate for address-keyed ObjC lookups: the host app's own
// classes/methods/IMPs always resolve; Shadow's own artifacts are always
// hidden; everything else keeps the existing restricted-image verdict.
BOOL shdw_objc_addr_is_hidden(const void* addr) {
    if(!addr) {
        return NO;
    }

    if(shdw_addr_in_main_image(addr)) {
        return NO;
    }

    uintptr_t a = (uintptr_t)addr;
    shdw_own_ranges_t* own = __atomic_load_n(&_shdw_own_ranges_published, __ATOMIC_ACQUIRE);

    for(uint32_t i = 0; i < own->count; i++) {
        if(a >= own->range[i].base && a < own->range[i].end) {
            return YES;
        }
    }

    return shdw_addr_is_restricted(addr);
}

// Same-file check against the main executable: exact string first, then
// stat device/inode so /var/jb and /private/preboot aliases agree.
static BOOL shdw_path_is_main_image(const char* path) {
    if(!path || !path[0]) {
        return NO;
    }

    const char* mainPath = _dyld_get_image_name(0);

    if(!mainPath || !mainPath[0]) {
        return NO;
    }

    if(strcmp(path, mainPath) == 0) {
        return YES;
    }

    struct stat a;
    struct stat b;

    if(stat(path, &a) == 0 && stat(mainPath, &b) == 0) {
        return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
    }

    return NO;
}

// Hiding predicate for path-keyed ObjC APIs (class_getImageName result,
// objc_copyImageNames, objc_copyClassNamesForImage, objc_copyClassesForImage):
// the host app's own image always resolves; Shadow artifacts and other
// protected images stay hidden.
BOOL shdw_objc_image_path_is_hidden(const char* path) {
    if(!path || !path[0]) {
        return NO;
    }

    if(shdw_path_is_main_image(path)) {
        return NO;
    }

    return shdw_is_shadow_runtime_image(path) || [_shadow isProtectedImagePath:@(path)];
}

// Class-object hiding: classify by the class's EXACT image path, never by
// span-based address ranges. Class metadata in the dyld shared cache lives in
// split/global ObjC regions whose addresses can fall inside the gaps of a
// union span (observed on-device: with hooks live,
// NSClassFromString(@"NSString")/NSClassFromString(@"NSObject") returned nil
// for external callers, and BoardServices' +[BSMutableServiceInterface
// interfaceWithIdentifier:] asserted on the nil class → SIGTRAP at startup).
// The host app's own classes always resolve (C-prime); Shadow artifacts stay
// hidden via the exact own-ranges spans; everything else is classified by the
// class's image path through the path-keyed predicate above.
BOOL shdw_objc_class_is_hidden(Class cls) {
    if(!cls) {
        return NO;
    }

    const void* addr = (__bridge const void *)cls;

    if(shdw_addr_in_main_image(addr)) {
        return NO;
    }

    uintptr_t a = (uintptr_t)addr;
    shdw_own_ranges_t* own = __atomic_load_n(&_shdw_own_ranges_published, __ATOMIC_ACQUIRE);

    for(uint32_t i = 0; i < own->count; i++) {
        if(a >= own->range[i].base && a < own->range[i].end) {
            return YES;
        }
    }

    if(!original_class_getImageName) {
        return NO;   // no native resolver → fail visible
    }

    const char* image = original_class_getImageName(cls);

    if(!image || !image[0]) {
        return NO;   // runtime-native class (no loadable image) → visible
    }

    return shdw_objc_image_path_is_hidden(image);
}


static const char* replaced_class_getImageName(Class cls) {
    // C0-2: Shadow's own code sees truth; every other caller is filtered.
    if(!isCallerExternal()) {
        return original_class_getImageName(cls);
    }

    // Protected class (its data lives in a protected image): report "no
    // image" — NULL, never a fake executable path (plan Wave 1c).
    if(shdw_objc_class_is_hidden(cls)) {
        return NULL;
    }

    const char* result = original_class_getImageName(cls);

    if(result && shdw_objc_image_path_is_hidden(result)) {
        return NULL;
    }

    return result;
}

static const char * _Nonnull * (*original_objc_copyImageNames)(unsigned int *outCount);
static const char * _Nonnull * replaced_objc_copyImageNames(unsigned int *outCount) {
    if(!isCallerExternal()) {
        return original_objc_copyImageNames(outCount);
    }

    // Always resolve through a local count (the original rejects
    // outCount == NULL), then build a malloc'd NULL-terminated filtered copy
    // and free the original. The name strings are BORROWED, not strdup'd:
    // objc_copyImageNames copies only the pointer array — the strings live in
    // the runtime's per-image storage and outlive the array, the same
    // lifetime stock callers rely on (they free() only the array, so strdup'd
    // strings would leak on every call). outCount == NULL still gets the
    // FILTERED array, and *outCount is only written when non-NULL. The old
    // truncate-at-exec heuristic is gone (plan Wave 1c).
    unsigned int localCount = 0;
    const char **result = original_objc_copyImageNames(&localCount);

    if(!result) {
        if(outCount) {
            *outCount = 0;
        }

        return NULL;
    }

    const char **filtered = malloc(((size_t)localCount + 1) * sizeof(char *));

    if(!filtered) {
        // malloc failure: fail soft with the stock list (the process is OOM).
        if(outCount) {
            *outCount = localCount;
        }

        return result;
    }

    unsigned int n = 0;

    for(unsigned int i = 0; i < localCount; i++) {
        const char* name = result[i];

        if(!name || shdw_objc_image_path_is_hidden(name)) {
            continue;
        }

        filtered[n] = name;
        n++;
    }

    filtered[n] = NULL;
    free(result);

    if(outCount) {
        *outCount = n;
    }

    return filtered;
}

static const char * _Nonnull * (*original_objc_copyClassNamesForImage)(const char* image, unsigned int *outCount);
static const char * _Nonnull * replaced_objc_copyClassNamesForImage(const char* image, unsigned int *outCount) {
    if(!isCallerExternal()) {
        return original_objc_copyClassNamesForImage(image, outCount);
    }

    if(shdw_objc_image_path_is_hidden(image)) {
        // Zero the count before returning NULL so callers can't misread a
        // stale count (plan Wave 1c).
        if(outCount) {
            *outCount = 0;
        }

        return NULL;
    }

    return original_objc_copyClassNamesForImage(image, outCount);
}
static IMP (*original_class_getMethodImplementation)(Class cls, SEL name);
static IMP replaced_class_getMethodImplementation(Class cls, SEL name) {
    if(!isCallerExternal()) {
        return original_class_getMethodImplementation(cls, name);
    }

    IMP result = original_class_getMethodImplementation(cls, name);

    // A visible class may have a legitimate third-party replacement IMP.
    // Hide the entire method surface only when the declaring class itself is
    // protected; ownerless IMP APIs cannot safely make this distinction.
    if(shdw_objc_class_is_hidden(cls)) {
        return NULL;
    }

    // Swizzling stealth: a detector reads a hooked system method's IMP here and
    // dladdr()s it, expecting a system image (a swizzle-origin check that reads
    // via class_getMethodImplementation, not method_getImplementation). Return
    // the original IMP for hooked methods so the reported IMP stays in its
    // genuine framework. Mirrors the method_getImplementation stealth in
    // objc_methodimpl.x.
    if(cls && name) {
        Method method = class_getInstanceMethod(cls, name);
        IMP original = method ? SHDWOriginalImplementationForMethod(method) : NULL;
        if(original) {
            return original;
        }
        if(name == sel_registerName("fileExistsAtPath:")) {
            void* hookOrig = shdw_universal_file_exists_original();
            if(hookOrig) return (IMP)hookOrig;
        }
        if(name == sel_registerName("isReadableFileAtPath:")) {
            void* hookOrig = shdw_universal_readable_file_original();
            if(hookOrig) return (IMP)hookOrig;
        }
        if(name == sel_registerName("canOpenURL:")) {
            void* hookOrig = SHDWCanOpenURLOriginal();
            if(hookOrig) return (IMP)hookOrig;
        }
        // Last resort: our replacement-IMP remap table (covers HookKit-owned
        // originals the SHDW method table never recorded).
        if(result) {
            const void* remapped = SHDWOriginalIMPForReplacement((const void*)result);
            if(remapped) return (IMP)remapped;
        }
    }

    return result;
}

// imp_getBlock is not a linkable symbol on all SDKs (added in iOS 16), so
// resolve it at runtime like dyld.x does for dlopen_internal, and guard NULL.
// Block ABI layout: isa, flags, reserved, invoke (offset 16).
typedef struct {
    void* isa;
    int flags;
    int reserved;
    void* invoke;
} shdw_block_layout_t;

static id (*original_imp_getBlock)(IMP anImp);
static id replaced_imp_getBlock(IMP anImp) {
    // C0-2: Shadow's own code sees truth; every other caller is filtered.
    if(!isCallerExternal()) {
        return original_imp_getBlock(anImp);
    }

    // Call the original with the correct id signature, then classify the
    // returned block's ABI invoke pointer (offset 16) — NOT the trampoline
    // IMP: an IMP created from a protected block must not be revealed, and
    // the trampoline's image says nothing about the block it dispatches to
    // (plan Wave 2).
    id block = original_imp_getBlock(anImp);

    if(!block) {
        return nil;
    }

    shdw_block_layout_t* layout = (__bridge shdw_block_layout_t *)block;

    if(shdw_objc_addr_is_hidden(layout->invoke)) {
        return nil;
    }

    return block;
}
void shdw_universal_objc(SHDWHookSession* hooks) {
    // %init(shadowhook_objc);
    // Public ObjC imports use HK3's existing-import route. Runtime-resolved
    // private symbols below still need the address route.
    [hooks hookRebindSymbol:@"class_getImageName" withReplacement:replaced_class_getImageName outOldPtr:(void **) &original_class_getImageName];
    [hooks hookRebindSymbol:@"objc_copyClassNamesForImage" withReplacement:replaced_objc_copyClassNamesForImage outOldPtr:(void **) &original_objc_copyClassNamesForImage];
    [hooks hookRebindSymbol:@"objc_copyImageNames" withReplacement:replaced_objc_copyImageNames outOldPtr:(void **) &original_objc_copyImageNames];
    [hooks hookRebindSymbol:@"class_getMethodImplementation" withReplacement:replaced_class_getMethodImplementation outOldPtr:(void **) &original_class_getMethodImplementation];

    void* imp_getBlock_ptr = dlsym(RTLD_DEFAULT, "imp_getBlock");
    if(imp_getBlock_ptr) {
        [hooks hookFunction:imp_getBlock_ptr withReplacement:replaced_imp_getBlock outOldPtr:(void **) &original_imp_getBlock];
    }
}

// Rebind the ObjC-introspection imports in a specific (late-loaded) image, so a
// detector framework dlopen'd after the ctor still routes
// class_getMethodImplementation through Shadow's swizzling-stealth filter.
// method_getImplementation is covered by objc_methodimpl.x's own image rebind.
void shdw_universal_objc_rebind_image(SHDWHookSession* hooks, const void* imageHeader) {
    if(!imageHeader || !original_class_getMethodImplementation) return;
    [hooks hookRebindSymbol:@"class_getMethodImplementation"
            withReplacement:replaced_class_getMethodImplementation
                   outOldPtr:NULL
              inCallerImage:imageHeader];
}
