// _GNU_SOURCE must precede every include: glibc's dlfcn.h only declares
// dladdr/Dl_info under it (Darwin declares them always; inert there).
#define _GNU_SOURCE

// Host-side unit test for the Swift vtable engine (native/hk_swift.c). Runs
// on the build machine, not the device: it drives the engine's core against a
// hand-built fake Swift class metadata blob, exercising the ABI offsets, the
// validation sequence, the vtable-base formula, the relative method-impl
// decode and the PAC pre-write self-check.
//
//   clang -Wall -Wextra -O2 -o /tmp/t tests/test_swift_abi.c && /tmp/t
//
// The engine's ptrauth macros are overridable; the host has no PAC hardware,
// so this test injects a simulated PAC (low 4 bits carry a signature derived
// from the discriminator) before including the engine. That makes the
// pre-write self-check genuinely discriminate a correct discriminator from a
// tampered one, exactly as the real ptrauth builtins do on arm64e.

#include "../native/hk_swift.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --- simulated PAC (identity would make the self-check trivially pass) -----
// sign(p, d) keeps p's address bits and stamps 4 bits of d; strip removes the
// stamp. The comparison sign(strip(old)) == old then holds iff the
// discriminator used to sign the stored value matches the one the engine
// blended. 16-byte alignment of the fake code pointers keeps strip exact.
#define HK_TEST_PAC_MASK 0xF
#define hk_strip_code(p)  ((void *)((uintptr_t)(p) & ~(uintptr_t)HK_TEST_PAC_MASK))
#define hk_strip_data(p)  (p)
#define hk_sign_code(p, d) ((void *)(((uintptr_t)(p) & ~(uintptr_t)HK_TEST_PAC_MASK) \
                                     | ((uintptr_t)(d) & HK_TEST_PAC_MASK)))
#define hk_blend_disc(p, x) (((uintptr_t)(p) << 1) ^ (uintptr_t)(x))

// The engine, in this translation unit so the macros above win (its own
// definitions are guarded with #ifndef).
#include "../native/hk_swift.c"

// --- test infrastructure ----------------------------------------------------

static int g_failures = 0;

#define CHECK(cond) do { \
    if(!(cond)) { \
        printf("  FAIL: %s (line %d)\n", #cond, __LINE__); \
        g_failures += 1; \
    } \
} while(0)

static int g_patch_calls = 0;
static void *g_patch_dst = NULL;
static uint8_t g_patch_bytes[8];

// Fake hk_native_patch_memory: records the write instead of touching memory.
// The engine's own definition (native/hk_native.c) is not linked here.
bool hk_native_patch_memory(void *target, const void *data, size_t size) {
    g_patch_calls += 1;
    g_patch_dst = target;
    memset(g_patch_bytes, 0, sizeof(g_patch_bytes));
    memcpy(g_patch_bytes, data, size < sizeof(g_patch_bytes) ? size : sizeof(g_patch_bytes));
    return true;
}

// The engine's swift_demangle hook: the framework layer owns this global on
// device; here the test defines it and points it at the identity fake below.
hk_swift_demangle_fn hk_swift_demangle = NULL;

// Fake swift_demangle: identity copy (the real one returns NULL for
// non-mangled input; identity lets the substring path be driven with ordinary
// C symbol names).
static char *identity_demangle(const char *mangled, size_t length, char *out, size_t *out_size, uint32_t flags) {
    (void)flags;

    if(!mangled || length == 0) {
        return NULL;
    }

    if(out) {
        memcpy(out, mangled, length);
        out[length] = '\0';

        if(out_size) {
            *out_size = length + 1;
        }

        return out;
    }

    char *copy = malloc(length + 1);

    if(!copy) {
        return NULL;
    }

    memcpy(copy, mangled, length);
    copy[length] = '\0';
    return copy;
}

// --- fake Swift class metadata ----------------------------------------------

// Fake method implementations: real (global, default-visibility) functions so
// dladdr resolves them through .dynsym — the engine matches names against
// dli_sname. 16-aligned so the simulated PAC strip recovers them exactly.
int fake_a(void) __attribute__((aligned(16)));
int fake_b(void) __attribute__((aligned(16)));
int fake_c(void) __attribute__((aligned(16)));
int fake_d(void) __attribute__((aligned(16)));

int fake_a(void) { return 1; }
int fake_b(void) { return 2; }
int fake_c(void) { return 3; }
int fake_d(void) { return 4; }

// A function whose symbol name looks like a mangled Swift name, so the
// engine's exact-mangled path (strcmp against dli_sname) can be tested.
extern int fake_swift_thing(void) __asm__("$s4test7fakeThingyyF");
int fake_swift_thing(void) { return 9; }

// TargetClassDescriptor replica (offsets must match the engine's constants:
// VTableDescriptorHeader at 0x2C, method descriptors at 0x34).
typedef struct {
    uint32_t flags;             // 0x00
    uint32_t parent;            // 0x04
    uint32_t name;              // 0x08
    uint32_t access_fn;         // 0x0C
    uint32_t metadata_access;   // 0x10
    uint32_t superclass_type;   // 0x14
    uint32_t neg_size;          // 0x18
    uint32_t pos_size;          // 0x1C
    uint32_t num_immediate;     // 0x20
    uint32_t num_fields;        // 0x24
    uint32_t field_vec;         // 0x28
    uint32_t vtable_offset;     // 0x2C
    uint32_t vtable_size;       // 0x30
    struct {
        uint32_t flags;         // 0x00: kind/instance/dynamic/async/extra
        int32_t impl;           // 0x04: self-relative
    } methods[4];               // 0x34
} fake_descriptor_t;

_Static_assert(offsetof(fake_descriptor_t, vtable_offset) == 0x2C, "descriptor VTableOffset at 0x2C");
_Static_assert(offsetof(fake_descriptor_t, vtable_size) == 0x30, "descriptor VTableSize at 0x30");
_Static_assert(offsetof(fake_descriptor_t, methods) == 0x34, "descriptor method array at 0x34");

#define FAKE_METADATA_SIZE  0x100
#define FAKE_VTABLE_WORDS   0x10        // vtable at metadata + 0x80

static uint8_t g_metadata[FAKE_METADATA_SIZE] __attribute__((aligned(16)));
static fake_descriptor_t g_desc;

// The methods each slot points at; slot i <-> methods[i].
static void *const g_fns[4] = { (void *)&fake_a, (void *)&fake_b, (void *)&fake_c, (void *)&fake_d };

static void *slot_ptr(uint32_t index) {
    return (void *)(g_metadata + FAKE_VTABLE_WORDS * 8 + (size_t)index * 8);
}

// Build a well-formed blob: a Swift class whose 4 own methods land in slots
// 0..3, each signed with disc = blend(slot, extra) where extra = index + 1.
static void blob_setup(void) {
    memset(g_metadata, 0, sizeof(g_metadata));
    memset(&g_desc, 0, sizeof(g_desc));

    *(uintptr_t *)(g_metadata + 0x20) = HK_SWIFT_METADATA_IS_SWIFT_BIT;   // Data
    *(uint32_t *)(g_metadata + 0x3C) = 0x18;                              // ClassAddressPoint (root class)
    *(uintptr_t *)(g_metadata + 0x40) = (uintptr_t)&g_desc;               // Description

    g_desc.flags = HK_SWIFT_DESC_KIND_CLASS | HK_SWIFT_DESC_CLASS_HAS_VTABLE;
    g_desc.vtable_offset = FAKE_VTABLE_WORDS;
    g_desc.vtable_size = 4;

    for(int i = 0; i < 4; i++) {
        g_desc.methods[i].flags = HK_SWIFT_METHOD_IS_INSTANCE
            | ((uint32_t)(i + 1) << HK_SWIFT_METHOD_EXTRA_SHIFT);
        g_desc.methods[i].impl = (int32_t)((char *)g_fns[i] - (char *)&g_desc.methods[i].impl);

        // What the runtime wrote when it initialized the vtable.
        uintptr_t disc = hk_blend_disc(slot_ptr(i), (uintptr_t)(i + 1));
        *(void **)slot_ptr(i) = hk_sign_code(g_fns[i], disc);
    }
}

// --- tests -------------------------------------------------------------------

static void test_constants(void) {
    printf("constants:\n");

    // Metadata offsets.
    _Static_assert(HK_SWIFT_METADATA_DATA_OFFSET == 0x20, "Data +0x20");
    _Static_assert(HK_SWIFT_METADATA_CLASS_ADDRESS_POINT_OFFSET == 0x3C, "ClassAddressPoint +0x3C");
    _Static_assert(HK_SWIFT_METADATA_DESCRIPTION_OFFSET == 0x40, "Description +0x40");
    _Static_assert(HK_SWIFT_METADATA_IS_SWIFT_BIT == 1, "is-Swift bit 0");

    // Descriptor offsets and flags.
    _Static_assert(HK_SWIFT_DESC_KIND_MASK == 0x1F, "kind bits 0-4");
    _Static_assert(HK_SWIFT_DESC_KIND_CLASS == 16, "Class kind == 16");
    _Static_assert(HK_SWIFT_DESC_IS_GENERIC == 0x80, "generic bit 7");
    _Static_assert(HK_SWIFT_DESC_METADATA_INIT_MASK == 0x3, "init kind = kind-specific bits 0-1");
    _Static_assert(HK_SWIFT_DESC_CLASS_HAS_VTABLE == (1u << 31), "hasVTable = bit 15 of kind-specific field");
    _Static_assert(HK_SWIFT_DESC_CLASS_HAS_OVERRIDE_TABLE == (1u << 30), "hasOverrideTable = bit 14 of kind-specific field");
    _Static_assert(HK_SWIFT_DESC_CLASS_HAS_RESILIENT_SUPERCLASS == (1u << 29), "hasResilientSuperclass = bit 13 of kind-specific field");
    _Static_assert(HK_SWIFT_DESC_VTABLE_OFFSET == 0x2C, "VTableOffset +0x2C");
    _Static_assert(HK_SWIFT_DESC_VTABLE_SIZE == 0x30, "VTableSize +0x30");
    _Static_assert(HK_SWIFT_DESC_METHODS == 0x34, "method descriptors +0x34");

    // Method descriptors.
    _Static_assert(HK_SWIFT_METHOD_DESC_SIZE == 8, "8-byte method descriptor");
    _Static_assert(HK_SWIFT_METHOD_FLAGS_OFFSET == 0, "flags first");
    _Static_assert(HK_SWIFT_METHOD_IMPL_OFFSET == 4, "impl second");
    _Static_assert(HK_SWIFT_METHOD_KIND_MASK == 0x0F, "method kind mask");
    _Static_assert(HK_SWIFT_METHOD_IS_INSTANCE == 0x10, "IsInstance bit 4");
    _Static_assert(HK_SWIFT_METHOD_IS_DYNAMIC == 0x20, "IsDynamic bit 5");
    _Static_assert(HK_SWIFT_METHOD_IS_ASYNC == 0x40, "IsAsync bit 6");
    _Static_assert(HK_SWIFT_METHOD_EXTRA_SHIFT == 16, "extra discriminator bits 16-31");

    // PAC recipe.
    _Static_assert(HK_SWIFT_PTRAUTH_KEY_FUNCTION_POINTER == 0, "ptrauth_key_asia == process-independent code");

    // Error codes.
    CHECK(HK_SWIFT_ERR_UNSUPPORTED < 0 && HK_SWIFT_ERR_WRITE < 0);
    printf("  PASS\n");
}

static void expect_error(int want_errno) {
    CHECK(hk_swift_last_error() == want_errno);
}

static void test_validation(void) {
    printf("validation sequence:\n");

    // 1. Null arguments.
    blob_setup();
    CHECK(!hk_swift_hook_slot(NULL, 0, (void *)&fake_a, NULL));
    expect_error(HK_SWIFT_ERR_ARG);
    CHECK(!hk_swift_hook_slot((Class)g_metadata, 0, NULL, NULL));
    expect_error(HK_SWIFT_ERR_ARG);

    // 2. Not a Swift class (Data bit 0 clear).
    blob_setup();
    *(uintptr_t *)(g_metadata + 0x20) = 0;
    CHECK(!hk_swift_hook_slot((Class)g_metadata, 0, (void *)&fake_a, NULL));
    expect_error(HK_SWIFT_ERR_NOT_SWIFT);

    // 3. Artificial/KVO subclass (null Description).
    blob_setup();
    *(uintptr_t *)(g_metadata + 0x40) = 0;
    CHECK(!hk_swift_hook_slot((Class)g_metadata, 0, (void *)&fake_a, NULL));
    expect_error(HK_SWIFT_ERR_NOT_SWIFT);

    // 4/5. Description not a class descriptor (struct kind).
    blob_setup();
    g_desc.flags = (g_desc.flags & ~HK_SWIFT_DESC_KIND_MASK) | 17;   // Struct
    CHECK(!hk_swift_hook_slot((Class)g_metadata, 0, (void *)&fake_a, NULL));
    expect_error(HK_SWIFT_ERR_NOT_CLASS_DESCRIPTOR);

    // 6. No vtable.
    blob_setup();
    g_desc.flags &= ~HK_SWIFT_DESC_CLASS_HAS_VTABLE;
    CHECK(!hk_swift_hook_slot((Class)g_metadata, 0, (void *)&fake_a, NULL));
    expect_error(HK_SWIFT_ERR_NO_VTABLE);

    // 7. Generic class.
    blob_setup();
    g_desc.flags |= HK_SWIFT_DESC_IS_GENERIC;
    CHECK(!hk_swift_hook_slot((Class)g_metadata, 0, (void *)&fake_a, NULL));
    expect_error(HK_SWIFT_ERR_UNSUPPORTED_LAYOUT);

    // 8. Resilient superclass.
    blob_setup();
    g_desc.flags |= HK_SWIFT_DESC_CLASS_HAS_RESILIENT_SUPERCLASS;
    CHECK(!hk_swift_hook_slot((Class)g_metadata, 0, (void *)&fake_a, NULL));
    expect_error(HK_SWIFT_ERR_UNSUPPORTED_LAYOUT);

    // 8b. Singleton/foreign metadata initialization (shifts the vtable header).
    blob_setup();
    g_desc.flags |= (1u << 16);     // kind-specific bits 0-1 = init kind 1
    CHECK(!hk_swift_hook_slot((Class)g_metadata, 0, (void *)&fake_a, NULL));
    expect_error(HK_SWIFT_ERR_UNSUPPORTED_LAYOUT);

    // 9. Index out of bounds.
    blob_setup();
    CHECK(!hk_swift_hook_slot((Class)g_metadata, 4, (void *)&fake_a, NULL));
    expect_error(HK_SWIFT_ERR_INVALID_INDEX);
    CHECK(!hk_swift_hook_slot((Class)g_metadata, 99, (void *)&fake_a, NULL));
    expect_error(HK_SWIFT_ERR_INVALID_INDEX);

    // 10. Async slot.
    blob_setup();
    g_desc.methods[1].flags |= HK_SWIFT_METHOD_IS_ASYNC;
    CHECK(!hk_swift_hook_slot((Class)g_metadata, 1, (void *)&fake_a, NULL));
    expect_error(HK_SWIFT_ERR_UNSUPPORTED_LAYOUT);

    // None of the failures above may have written anything.
    CHECK(g_patch_calls == 0);

    printf("  PASS\n");
}

static void test_hook_by_index(void) {
    printf("hook by index (vtable-base formula + relative impl decode):\n");

    // Hook slot 1; the write must land exactly on (char*)cls + VTableOffset*8
    // + 1*8, and carry the replacement re-signed with blend(slot, extra=2).
    blob_setup();
    g_patch_calls = 0;
    void *orig = NULL;

    CHECK(hk_swift_hook_slot((Class)g_metadata, 1, (void *)&fake_c, &orig));
    CHECK(g_patch_calls == 1);
    CHECK(g_patch_dst == slot_ptr(1));
    CHECK(orig == (void *)&fake_b);

    uintptr_t disc = hk_blend_disc(slot_ptr(1), 2);
    void *want = hk_sign_code((void *)&fake_c, disc);
    CHECK(memcmp(g_patch_bytes, &want, sizeof(want)) == 0);

    // The engine must not have touched the other slots.
    CHECK(*(void **)slot_ptr(0) == hk_sign_code((void *)&fake_a, hk_blend_disc(slot_ptr(0), 1)));
    CHECK(*(void **)slot_ptr(2) == hk_sign_code((void *)&fake_c, hk_blend_disc(slot_ptr(2), 3)));

    // Hook slot 0 as well (multiple independent hooks in one class).
    g_patch_calls = 0;
    orig = NULL;

    CHECK(hk_swift_hook_slot((Class)g_metadata, 0, (void *)&fake_d, &orig));
    CHECK(g_patch_calls == 1);
    CHECK(g_patch_dst == slot_ptr(0));
    CHECK(orig == (void *)&fake_a);

    printf("  PASS\n");
}

static void test_self_check(void) {
    printf("pre-write PAC self-check:\n");

    // Tampered discriminator: simulate a runtime that signed slot 1 with a
    // different extra discriminator than the method descriptor records. The
    // engine must refuse BEFORE writing anything.
    blob_setup();
    uintptr_t tampered = hk_blend_disc(slot_ptr(1), 2 ^ 1);
    *(void **)slot_ptr(1) = hk_sign_code((void *)&fake_b, tampered);
    g_patch_calls = 0;

    CHECK(!hk_swift_hook_slot((Class)g_metadata, 1, (void *)&fake_c, NULL));
    expect_error(HK_SWIFT_ERR_PAC_MISMATCH);
    CHECK(g_patch_calls == 0);

    // The matching discriminator passes (covered per-slot by hook_by_index,
    // re-checked here so the section stands alone).
    blob_setup();
    g_patch_calls = 0;

    CHECK(hk_swift_hook_slot((Class)g_metadata, 2, (void *)&fake_a, NULL));
    CHECK(g_patch_calls == 1);
    CHECK(g_patch_dst == slot_ptr(2));

    printf("  PASS\n");
}

static void test_find_by_name(void) {
    printf("find slot by name:\n");

    // Demangled substring match: every slot's dli_sname resolves, and the
    // identity demangle makes strstr match ordinary C names.
    blob_setup();
    uint32_t index = 99;
    CHECK(hk_swift_find_slot((Class)g_metadata, "fake_c", &index));
    CHECK(index == 2);

    // No match.
    CHECK(!hk_swift_find_slot((Class)g_metadata, "no_such_method", &index));
    expect_error(HK_SWIFT_ERR_NOT_FOUND);

    // Ambiguous: two slots sharing one implementation.
    blob_setup();
    g_desc.methods[3].impl = (int32_t)((char *)&fake_a - (char *)&g_desc.methods[3].impl);   // slot 3 now also fake_a
    *(void **)slot_ptr(3) = hk_sign_code((void *)&fake_a, hk_blend_disc(slot_ptr(3), 4));
    CHECK(!hk_swift_find_slot((Class)g_metadata, "fake_a", &index));
    expect_error(HK_SWIFT_ERR_AMBIGUOUS);

    // Exact mangled match (and its "_$s" form): the fake_swift_thing symbol
    // is literally named "$s4test7fakeThingyyF".
    blob_setup();
    g_desc.methods[3].impl = (int32_t)((char *)&fake_swift_thing - (char *)&g_desc.methods[3].impl);
    *(void **)slot_ptr(3) = hk_sign_code((void *)&fake_swift_thing, hk_blend_disc(slot_ptr(3), 4));

    CHECK(hk_swift_find_slot((Class)g_metadata, "$s4test7fakeThingyyF", &index));
    CHECK(index == 3);
    CHECK(hk_swift_find_slot((Class)g_metadata, "_$s4test7fakeThingyyF", &index));
    CHECK(index == 3);

    // A mangled query that matches nothing.
    CHECK(!hk_swift_find_slot((Class)g_metadata, "$s4test7noSuchThingyyF", &index));
    expect_error(HK_SWIFT_ERR_NOT_FOUND);

    printf("  PASS\n");
}

int main(void) {
    hk_swift_demangle = identity_demangle;

    test_constants();
    test_validation();
    test_hook_by_index();
    test_self_check();
    test_find_by_name();

    if(g_failures) {
        printf("%d check(s) FAILED\n", g_failures);
        return 1;
    }

    printf("all swift ABI tests passed\n");
    return 0;
}
