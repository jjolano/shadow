#ifndef hk_inline_guard_h
#define hk_inline_guard_h

#include <stdbool.h>
#include <stdint.h>

// Process-wide inline-ownership guard: prevents HookKit-vs-HookKit
// contention — two HKSubstitutor instances (or one instance hooking twice)
// installing DIFFERENT inline hooks on the same function address through
// DIFFERENT inline backends (native/Dobby/Frida/litehook-inline/ElleKit/
// Substrate/Substitute), which would double-patch one prologue.
//
// Pure C on purpose: the host-side test compiles this file directly, with no
// Foundation/ObjC in the picture.

// Reserve an inline hook target. Returns:
//   HK_GUARD_OK        - target free (or same type chaining); hook may
//                        proceed; entry reserved
//   HK_GUARD_DUP       - same address + same replacement already hooked:
//                        caller should treat as idempotent success
//                        (outOrig receives the saved original)
//   HK_GUARD_BLOCKED   - same address, DIFFERENT replacement, DIFFERENT
//                        backend type: caller must NOT invoke the backend
//                        (nothing was written)
// Same backend type + different replacement is allowed (provider chaining)
// and logs.
typedef enum {
    HK_GUARD_OK = 0,
    HK_GUARD_DUP,
    HK_GUARD_BLOCKED
} hk_guard_result_t;

hk_guard_result_t hk_inline_guard_reserve(uintptr_t address, void *replacement, int backendType, void **outOrig);

// Called after the backend call: HK_OK -> store origValue; HK_ERR -> mark
// tainted (keep entry so later different hooks still block);
// HK_ERR_NOT_SUPPORTED -> release entry (backend wrote nothing).
// status is int for host-testability.
void hk_inline_guard_update(uintptr_t address, int status, void *origValue);

#endif
