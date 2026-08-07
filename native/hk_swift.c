// _GNU_SOURCE: glibc hides dladdr behind it (Darwin declares it always; the
// define is inert there). Keeps the host-side test build warning-free.
#define _GNU_SOURCE
#include "hk_swift.h"
#include "hk_native.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// dladdr's info struct: Darwin (Dl_info) and glibc (Dl_info as of 2.34) both
// provide it; only non-glibc non-Darwin hosts (e.g. musl) need the fallback.
#if !defined(__APPLE__) && !defined(__GLIBC__)
typedef struct {
    const char *dli_fname;
    void *dli_fbase;
    const char *dli_sname;
    void *dli_saddr;
} Dl_info;
#endif

// Pointer authentication. On arm64e these use the real ptrauth builtins; on
// arm64 and armv7 they are identity, which is exactly what the ABI wants
// (slots are plain pointers there). The host-side ABI test pre-defines all
// four macros to a simulated PAC before including this file so the
// pre-write self-check discriminates real from tampered discriminators on a
// machine with no PAC hardware.
#ifndef hk_strip_code
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#define hk_strip_code(p)  ptrauth_strip((p), ptrauth_key_function_pointer)
#define hk_strip_data(p)  ptrauth_strip((p), ptrauth_key_process_independent_data)
#define hk_sign_code(p, d) ptrauth_sign_unauthenticated((void *)(p), ptrauth_key_function_pointer, (d))
#define hk_blend_disc(p, x) ptrauth_blend_discriminator((p), (x))
#else
// Identity, but still consume the arguments so `extra`/`disc` stay "used"
// under -Werror on non-PAC builds.
#define hk_strip_code(p)  (p)
#define hk_strip_data(p)  (p)
#define hk_sign_code(p, d) ((void)(d), (void *)(p))
#define hk_blend_disc(p, x) ((void)(p), (void)(x), (uintptr_t)0)
#endif
#endif

static int hk_swift_errno = 0;

bool hk_swift_supported(void) {
#if defined(__arm64__) || defined(__aarch64__)
    return true;
#else
    return false;
#endif
}

int hk_swift_last_error(void) {
    return hk_swift_errno;
}

// Validation steps 1-8 of the shared core. On success fills in the vtable
// base, the method descriptor array and the own-method count.
static bool hk_swift_resolve(Class cls, void ***out_vtable, const uint32_t **out_methods, uint32_t *out_count) {
    if(!cls) {
        hk_swift_errno = HK_SWIFT_ERR_ARG;
        return false;
    }

    // 2. Swift class? The low bit of the class metadata Data word is set for
    // Swift metatypes (SWIFT_CLASS_IS_SWIFT_MASK = 1 on Swift 5 runtimes).
    uintptr_t data = *(const uintptr_t *)((const char *)cls + HK_SWIFT_METADATA_DATA_OFFSET);

    if(!(data & HK_SWIFT_METADATA_IS_SWIFT_BIT)) {
        hk_swift_errno = HK_SWIFT_ERR_NOT_SWIFT;
        return false;
    }

    // 3. Description is null for artificial subclasses (KVO dynamic
    // subclasses) -- there is no descriptor to hook.
    uintptr_t description_signed = *(const uintptr_t *)((const char *)cls + HK_SWIFT_METADATA_DESCRIPTION_OFFSET);

    if(!description_signed) {
        hk_swift_errno = HK_SWIFT_ERR_NOT_SWIFT;
        return false;
    }

    // 4. Signed absolute pointer on arm64e (key process_independent_data).
    // A wrong strip key is caught by the descriptor checks below.
    const char *descriptor = (const char *)hk_strip_data((void *)description_signed);

    // 5. Class descriptor?
    uint32_t flags = *(const uint32_t *)descriptor;

    if((flags & HK_SWIFT_DESC_KIND_MASK) != HK_SWIFT_DESC_KIND_CLASS) {
        hk_swift_errno = HK_SWIFT_ERR_NOT_CLASS_DESCRIPTOR;
        return false;
    }

    // 6. No vtable means no own methods to hook.
    if(!(flags & HK_SWIFT_DESC_CLASS_HAS_VTABLE)) {
        hk_swift_errno = HK_SWIFT_ERR_NO_VTABLE;
        return false;
    }

    // 7/8. Generic classes and classes with resilient superclasses have
    // runtime-sized metadata; the fixed-offset layout below does not apply.
    if(flags & HK_SWIFT_DESC_IS_GENERIC) {
        hk_swift_errno = HK_SWIFT_ERR_UNSUPPORTED_LAYOUT;
        return false;
    }

    if(flags & HK_SWIFT_DESC_CLASS_HAS_RESILIENT_SUPERCLASS) {
        hk_swift_errno = HK_SWIFT_ERR_UNSUPPORTED_LAYOUT;
        return false;
    }

    // Singleton/foreign metadata initialization inserts a trailing object
    // before the VTableDescriptorHeader (Metadata.h TargetClassDescriptor),
    // moving it off +0x2C. Fail closed: the fixed-offset read below would
    // otherwise decode garbage.
    if((flags >> 16) & HK_SWIFT_DESC_METADATA_INIT_MASK) {
        hk_swift_errno = HK_SWIFT_ERR_UNSUPPORTED_LAYOUT;
        return false;
    }

    uint32_t vtable_offset = *(const uint32_t *)(descriptor + HK_SWIFT_DESC_VTABLE_OFFSET);
    uint32_t vtable_size = *(const uint32_t *)(descriptor + HK_SWIFT_DESC_VTABLE_SIZE);

    // Vtable base relative to the metadata address point -- the AnyClass
    // pointer itself (initClassVTable: classWords = self; &classWords[vtableOffset + i]).
    *out_vtable = (void **)((const char *)cls + (size_t)vtable_offset * HK_SWIFT_VTABLE_ENTRY_SIZE);
    *out_methods = (const uint32_t *)(descriptor + HK_SWIFT_DESC_METHODS);
    *out_count = vtable_size;
    return true;
}

// Resolve a method descriptor's implementation: int32 self-relative to the
// Impl field's own address (TargetCompactFunctionPointer; no PAC on the
// relative value).
static void *hk_swift_method_impl(const uint32_t *method) {
    const char *impl_field = (const char *)method + HK_SWIFT_METHOD_IMPL_OFFSET;
    return (void *)(impl_field + *(const int32_t *)impl_field);
}

bool hk_swift_find_slot(Class cls, const char *name, uint32_t *out_index) {
    hk_swift_errno = 0;

    if(!cls || !name || !name[0]) {
        hk_swift_errno = HK_SWIFT_ERR_ARG;
        return false;
    }

    void **vtable = NULL;
    const uint32_t *methods = NULL;
    uint32_t size = 0;

    if(!hk_swift_resolve(cls, &vtable, &methods, &size)) {
        return false;
    }

    // "$s..." / "_$s..." queries are exact matches against the slot's symbol
    // name (dli_sname has no leading underscore, so "_$s" is stripped).
    const char *probe = name;
    bool mangled_exact = (strncmp(name, "$s", 2) == 0);

    if(strncmp(name, "_$s", 3) == 0) {
        mangled_exact = true;
        probe = name + 1;
    }

    uint32_t *matched = malloc((size_t)size * sizeof(uint32_t));

    if(!matched) {
        // OOM: no dedicated code; ARG is the generic failure.
        hk_swift_errno = HK_SWIFT_ERR_ARG;
        return false;
    }

    unsigned matches = 0;

    for(uint32_t i = 0; i < size; i++) {
        const uint32_t *method = methods + i * (HK_SWIFT_METHOD_DESC_SIZE / sizeof(uint32_t));

        // Async slots are signed with the slot address alone (no extra
        // discriminator); the recipe below cannot resign them.
        if(*method & HK_SWIFT_METHOD_IS_ASYNC) {
            continue;
        }

        void *impl = hk_swift_method_impl(method);
        Dl_info info;

        if(!impl || !dladdr(impl, &info) || !info.dli_sname) {
            continue;
        }

        bool hit = false;

        if(mangled_exact) {
            hit = (strcmp(probe, info.dli_sname) == 0);
        } else if(hk_swift_demangle) {
            char *demangled = hk_swift_demangle(info.dli_sname, strlen(info.dli_sname), NULL, NULL, 0);

            if(demangled) {
                hit = (strstr(demangled, name) != NULL);
                free(demangled);
            }
        }

        if(hit) {
            matched[matches++] = i;
        }
    }

    if(matches == 0) {
        fprintf(stderr, "[HookKit] hk_swift: no vtable slot matches '%s'\n", name);
        free(matched);
        hk_swift_errno = HK_SWIFT_ERR_NOT_FOUND;
        return false;
    }

    if(matches > 1) {
        // Never a silent first match: report every candidate.
        fprintf(stderr, "[HookKit] hk_swift: name '%s' is ambiguous (%u matching slots); candidates:\n", name, matches);

        for(unsigned c = 0; c < matches; c++) {
            const uint32_t *method = methods + matched[c] * (HK_SWIFT_METHOD_DESC_SIZE / sizeof(uint32_t));
            void *impl = hk_swift_method_impl(method);
            Dl_info info;

            if(dladdr(impl, &info) && info.dli_sname) {
                if(hk_swift_demangle) {
                    char *demangled = hk_swift_demangle(info.dli_sname, strlen(info.dli_sname), NULL, NULL, 0);

                    if(demangled) {
                        fprintf(stderr, "[HookKit] hk_swift:   slot %u -> %s\n", matched[c], demangled);
                        free(demangled);
                        continue;
                    }
                }

                fprintf(stderr, "[HookKit] hk_swift:   slot %u -> %s\n", matched[c], info.dli_sname);
            }
        }

        free(matched);
        hk_swift_errno = HK_SWIFT_ERR_AMBIGUOUS;
        return false;
    }

    *out_index = matched[0];
    free(matched);
    return true;
}

bool hk_swift_hook_slot(Class cls, uint32_t index, void *replacement, void **out_orig) {
    hk_swift_errno = 0;

    if(!cls || !replacement) {
        hk_swift_errno = HK_SWIFT_ERR_ARG;
        return false;
    }

    void **vtable = NULL;
    const uint32_t *methods = NULL;
    uint32_t size = 0;

    if(!hk_swift_resolve(cls, &vtable, &methods, &size)) {
        return false;
    }

    // 9. Bounds: slot i <-> method descriptor i, declaration order.
    if(index >= size) {
        hk_swift_errno = HK_SWIFT_ERR_INVALID_INDEX;
        return false;
    }

    const uint32_t *method = methods + (size_t)index * (HK_SWIFT_METHOD_DESC_SIZE / sizeof(uint32_t));

    // 10. Async methods are signed with the slot address alone; reject.
    if(*method & HK_SWIFT_METHOD_IS_ASYNC) {
        hk_swift_errno = HK_SWIFT_ERR_UNSUPPORTED_LAYOUT;
        return false;
    }

    void **slot = vtable + index;
    uintptr_t extra = (uintptr_t)(*method >> HK_SWIFT_METHOD_EXTRA_SHIFT);
    uintptr_t disc = hk_blend_disc((void *)slot, extra);

    void *old = *slot;

    // Pre-write self-check (load-bearing on arm64e): the live slot value must
    // re-sign to itself under the recipe above. This validates the whole
    // signing scheme against a real runtime slot and makes a wrong
    // description-strip key fail cleanly at the descriptor checks instead.
    if(hk_sign_code(hk_strip_code(old), disc) != old) {
        hk_swift_errno = HK_SWIFT_ERR_PAC_MISMATCH;
        return false;
    }

    void *new_value = hk_sign_code(replacement, disc);

    // Single aligned pointer store via hk_native_patch_memory, which handles
    // read-only __DATA_CONST by breaking the COW (VM_PROT_COPY) or remapping
    // a private copy.
    if(!hk_native_patch_memory(slot, &new_value, sizeof(new_value))) {
        hk_swift_errno = HK_SWIFT_ERR_WRITE;
        return false;
    }

    if(out_orig) {
        *out_orig = hk_strip_code(old);
    }

    return true;
}

bool hk_swift_hook_method(Class cls, const char *name, void *replacement, void **out_orig) {
    hk_swift_errno = 0;

    if(!cls || !name || !name[0] || !replacement) {
        hk_swift_errno = HK_SWIFT_ERR_ARG;
        return false;
    }

    if(!hk_swift_supported()) {
        hk_swift_errno = HK_SWIFT_ERR_UNSUPPORTED;
        return false;
    }

    uint32_t index = 0;

    if(!hk_swift_find_slot(cls, name, &index)) {
        return false;
    }

    return hk_swift_hook_slot(cls, index, replacement, out_orig);
}

bool hk_swift_hook_vtable_slot(Class cls, uint32_t index, void *replacement, void **out_orig) {
    hk_swift_errno = 0;

    if(!cls || !replacement) {
        hk_swift_errno = HK_SWIFT_ERR_ARG;
        return false;
    }

    if(!hk_swift_supported()) {
        hk_swift_errno = HK_SWIFT_ERR_UNSUPPORTED;
        return false;
    }

    return hk_swift_hook_slot(cls, index, replacement, out_orig);
}
