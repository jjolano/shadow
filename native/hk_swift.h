#ifndef hk_swift_h
#define hk_swift_h

// HookKit's Swift vtable-hooking engine: rewrites the target's method slot in
// its Swift class metadata vtable, so Swift callers of the hooked method
// dispatch to the replacement. No Swift runtime APIs are called -- the layout
// below is read directly and validated before anything is written.
//
// arm64/arm64e only (needs the metadata layouts and, on arm64e, ptrauth
// handling). On other architectures hk_swift_supported() is false and every
// entry point reports HK_SWIFT_ERR_UNSUPPORTED.
//
// Fail-closed design: every field is validated against the Swift 5 ABI before
// the slot write, and on arm64e a pre-write self-check re-signs the live slot
// value with the recipe below -- a wrong recipe (or a non-vtable slot) fails
// cleanly instead of corrupting memory.
//
// All offsets/bit positions below were verified against apple/swift
// swift-5.9.2-RELEASE (include/swift/ABI/Metadata.h, MetadataValues.h,
// stdlib/public/runtime/Metadata.cpp, lib/IRGen/{GenMeta,MetadataLayout,
// MetadataVisitor,ClassMetadataVisitor,NominalMetadataVisitor}.cpp/h).
// Note on the vtable base: TargetVTableDescriptorHeader.VTableOffset is
// relative to the metadata *address point* (the AnyClass pointer itself) --
// Metadata.cpp initClassVTable computes
// `classWords = (void **)self; &classWords[vtableOffset + i]` with no
// ClassAddressPoint term, and GenMeta.cpp emits `getStaticVTableOffset()`
// which MetadataLayout.cpp computes as `NextOffset - AddressPoint`. The
// ClassAddressPoint field (+0x3C) is therefore NOT part of the vtable base.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Internal to the framework: HookKit's only exported symbol is _HKSubstitutor
// (see HookKit.tbd), and these must not join the dynamic export table.
#ifndef HK_INTERNAL
#define HK_INTERNAL __attribute__((visibility("hidden")))
#endif

// Class is an Objective-C type; keep this header compilable as plain C so the
// host-side ABI test (no ObjC runtime on the build machine) can include it.
#if !defined(__OBJC__) && !defined(Class)
typedef struct objc_class *Class;
#endif

#pragma mark - Offsets and flags (Swift 5 ABI, 64-bit, ObjC-interop classes)

// TargetAnyClassMetadataObjCInterop: isa +0x00, superclass +0x08,
// cacheData[2] +0x10, Data +0x20 -- Metadata.h:826-835
// ("the compiler sets the low bit in order to indicate that this is a Swift
//  metatype" -- the bit is SWIFT_CLASS_IS_SWIFT_MASK, = 1 on Swift 5 runtimes).
#define HK_SWIFT_METADATA_DATA_OFFSET          0x20
#define HK_SWIFT_METADATA_IS_SWIFT_BIT         0x1

// TargetClassMetadata: Flags +0x28 ... ClassSize +0x38,
// ClassAddressPoint +0x3C (Metadata.h:912), Description +0x40
// (Metadata.h:921). Description is a signed absolute pointer on arm64e
// (__ptrauth_swift_type_descriptor: key process_independent_data) and null
// for artificial subclasses (KVO).
#define HK_SWIFT_METADATA_CLASS_ADDRESS_POINT_OFFSET 0x3C
#define HK_SWIFT_METADATA_DESCRIPTION_OFFSET   0x40

// TargetContextDescriptor/Flags: kind in bits 0-4 (MetadataValues.h:1568
// `Value & 0x1Fu`), generic in bit 7 (MetadataValues.h:1573 `Value & 0x80u`),
// kind-specific flags in bits 16-31 (MetadataValues.h:1590 `Value >> 16u`).
#define HK_SWIFT_DESC_KIND_MASK                0x1F
#define HK_SWIFT_DESC_KIND_CLASS               16      // MetadataValues.h:1532 (Class = Type_First = 16)
#define HK_SWIFT_DESC_IS_GENERIC               0x80

// Kind-specific class flags (MetadataValues.h:1683-1693): Class_HasVTable =
// bit 15 of the 16-bit kind-specific field = overall bit 31; likewise
// Class_HasOverrideTable = 14 -> bit 30; Class_HasResilientSuperclass = 13 ->
// bit 29. MetadataInitialization (kind-specific bits 0-1, MetadataValues.h
// TypeContextDescriptorFlags.MetadataInitialization, width 2) must be
// "none" (0): Singleton/Foreign metadata initialization inserts a trailing
// object before the VTableDescriptorHeader (Metadata.h TargetClassDescriptor
// TrailingGenericContextObjects order), which would move the vtable header
// off +0x2C. Verified empirically: root classes and subclasses whose
// superclass is in the same module keep init kind 0 even under
// -enable-library-evolution; cross-module Swift superclasses set
// hasResilientSuperclass instead and are rejected anyway.
#define HK_SWIFT_DESC_METADATA_INIT_MASK     0x3
#define HK_SWIFT_DESC_CLASS_HAS_VTABLE         (1u << 31)
#define HK_SWIFT_DESC_CLASS_HAS_OVERRIDE_TABLE (1u << 30)
#define HK_SWIFT_DESC_CLASS_HAS_RESILIENT_SUPERCLASS (1u << 29)

// TargetClassDescriptor (non-generic, non-resilient, no override table):
// ContextDescriptor 0x00-0x10, TypeContextDescriptor +0x10 (metadata access
// function), SuperclassType +0x14, MetadataNegativeSizeInWords +0x18,
// MetadataPositiveSizeInWords +0x1C, NumImmediateMembers +0x20,
// NumFields +0x24, FieldOffsetVectorOffset +0x28 (Metadata.h
// TargetClassDescriptor), then the trailing VTableDescriptorHeader
// (Metadata.h:609): VTableOffset +0x2C, VTableSize +0x30 (words;
// Metadata.h:619,626), then VTableSize x TargetMethodDescriptor at +0x34.
#define HK_SWIFT_DESC_VTABLE_OFFSET            0x2C
#define HK_SWIFT_DESC_VTABLE_SIZE              0x30
#define HK_SWIFT_DESC_METHODS                  0x34

// TargetMethodDescriptor (Metadata.h:582): { MethodDescriptorFlags Flags;
// union { TargetCompactFunctionPointer Impl; ... } } -- 8 bytes, no name
// field. Impl is an int32 self-relative offset from the field's own address.
// Flags (MetadataValues.h:348-352): kind 0x0F (Method=0, Init=1), instance
// 0x10, dynamic 0x20, async 0x40, extra discriminator in bits 16-31.
#define HK_SWIFT_METHOD_DESC_SIZE              8
#define HK_SWIFT_METHOD_FLAGS_OFFSET           0
#define HK_SWIFT_METHOD_IMPL_OFFSET            4
#define HK_SWIFT_METHOD_KIND_MASK              0x0F
#define HK_SWIFT_METHOD_IS_INSTANCE            0x10
#define HK_SWIFT_METHOD_IS_DYNAMIC             0x20
#define HK_SWIFT_METHOD_IS_ASYNC               0x40
#define HK_SWIFT_METHOD_EXTRA_SHIFT            16

// Vtable base: slot i lives at
//   (char *)cls + VTableOffset * sizeof(void *) + i * sizeof(void *)
// (see the note at the top of this header for why ClassAddressPoint is not
// part of the formula; Metadata.cpp:3250-3263 initClassVTable).
#define HK_SWIFT_VTABLE_ENTRY_SIZE             ((size_t)8)

// Pointer authentication (arm64e only; the macros are identity elsewhere):
// vtable slots are signed with ptrauth_key_function_pointer and the
// discriminator blend of the slot address with the method's extra
// discriminator (Metadata.cpp:3260-3263 swift_ptrauth_init_code_or_data);
// the class descriptor pointer is signed with ptrauth_key_process_independent_data.
#define HK_SWIFT_PTRAUTH_KEY_FUNCTION_POINTER  ((int)0)   // ptrauth_key_asia == process_independent_code

#pragma mark - Error codes (hk_swift_last_error)

#define HK_SWIFT_ERR_UNSUPPORTED          (-1)    // not arm64/arm64e
#define HK_SWIFT_ERR_NOT_SWIFT            (-2)    // not a Swift class (or artificial/KVO subclass)
#define HK_SWIFT_ERR_NOT_CLASS_DESCRIPTOR (-3)    // descriptor is not a class descriptor
#define HK_SWIFT_ERR_NO_VTABLE            (-4)    // class has no vtable (no methods)
#define HK_SWIFT_ERR_UNSUPPORTED_LAYOUT   (-5)    // generic / resilient superclass / async method
#define HK_SWIFT_ERR_NOT_FOUND            (-6)    // name matched no vtable slot
#define HK_SWIFT_ERR_AMBIGUOUS            (-7)    // name matched more than one vtable slot
#define HK_SWIFT_ERR_PAC_MISMATCH         (-8)    // pre-write self-check failed (wrong signature recipe or already-hooked slot)
#define HK_SWIFT_ERR_INVALID_INDEX        (-9)    // index >= vtable size
#define HK_SWIFT_ERR_ARG                  (-10)   // null/invalid argument
#define HK_SWIFT_ERR_WRITE                (-11)   // slot write failed (hk_native_patch_memory)

#pragma mark - swift_demangle (resolved by the framework layer)

// char *swift_demangle(const char *mangledName, size_t mangledNameLength,
//                      char *outputBuffer, size_t *outputBufferSize,
//                      uint32_t flags)
// Flags must be 0. With outputBuffer == NULL the result is malloc'd (caller
// free()s); NULL when the input is not a mangled name.
typedef char *(*hk_swift_demangle_fn)(const char *, size_t, char *, size_t *, uint32_t);

// Owned by HKSubstitutor.m (resolved once by swift_available); the engine
// reads it for name-based lookup. NULL means only exact mangled names match.
HK_INTERNAL extern hk_swift_demangle_fn hk_swift_demangle;

#pragma mark - API

// True when this build can hook Swift vtables at all (arm64/arm64e).
HK_INTERNAL bool hk_swift_supported(void);

// Error from the most recent failing call. Process-wide, not per-thread: read
// it immediately after the call that failed.
HK_INTERNAL int hk_swift_last_error(void);

// Hook a Swift class method by name. `name` semantics:
//   - "$s..." or "_$s..."  -> exact match against the slot implementation's
//     symbol name (dladdr dli_sname, mangled form, leading underscore dropped)
//   - anything else        -> substring (case-sensitive) match against the
//     demangled name (swift_demangle of dli_sname)
// Requires EXACTLY ONE matching slot: zero -> NOT_FOUND, more -> AMBIGUOUS
// (never a silent first match).
HK_INTERNAL bool hk_swift_hook_method(Class cls, const char *name, void *replacement, void **out_orig);

// Hook a Swift class method by vtable slot index (declaration order, see
// hk_swift_hook_slot).
HK_INTERNAL bool hk_swift_hook_vtable_slot(Class cls, uint32_t index, void *replacement, void **out_orig);

// Shared core. `index` is the declaration order of the class's own methods
// (slot i <-> method descriptor i, Metadata.cpp initClassVTable). On success
// *out_orig receives the original implementation as an unsigned code pointer
// (PAC-stripped on arm64e).
//
// Validation, fail closed and in order, BEFORE any write:
//   1. cls/replacement non-null                      -> ARG
//   2. metadata Data bit0 set (Swift class)          -> NOT_SWIFT
//   3. Description non-null (not artificial/KVO)     -> NOT_SWIFT
//   4. strip Description (process_independent_data)  -> descriptor
//   5. descriptor kind == Class                      -> NOT_CLASS_DESCRIPTOR
//   6. class_hasVTable                               -> NO_VTABLE
//   7. not generic                                   -> UNSUPPORTED_LAYOUT
//   8. no resilient superclass                       -> UNSUPPORTED_LAYOUT
//   9. metadata initialization kind == none          -> UNSUPPORTED_LAYOUT
//  10. index < VTableSize                            -> INVALID_INDEX
//  11. slot's method not async                       -> UNSUPPORTED_LAYOUT
// Then: read the slot, blend the discriminator, re-sign the old value and
// compare (PAC_MISMATCH on failure), sign the replacement, write through
// hk_native_patch_memory (handles read-only __DATA_CONST via
// VM_PROT_COPY + vm_remap).
//
// Not gated on hk_swift_supported(): the two entry points above check it, and
// this core is hidden so nothing else can reach it on unsupported archs.
HK_INTERNAL bool hk_swift_hook_slot(Class cls, uint32_t index, void *replacement, void **out_orig);

// Name resolution used by hk_swift_hook_method, exposed for the host-side
// test. Same matching rules and uniqueness requirement; on success
// *out_index receives the unique slot.
HK_INTERNAL bool hk_swift_find_slot(Class cls, const char *name, uint32_t *out_index);

#endif
