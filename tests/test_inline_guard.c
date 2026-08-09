#include <assert.h>
#include <stdio.h>

#include "../Internal/HKInlineGuard.h"

// Host-side test for the process-wide inline-ownership guard. Pure C, runs
// on the build machine; compile with:
//   clang -Wall -Wextra -O2 -o test_inline_guard tests/test_inline_guard.c Internal/HKInlineGuard.c

static void *fn1 = (void *)(uintptr_t)0x1000;
static void *fn2 = (void *)(uintptr_t)0x2000;
static void *repA = (void *)(uintptr_t)0x5000;
static void *repB = (void *)(uintptr_t)0x6000;
static void *repC = (void *)(uintptr_t)0x7000;

int main(void) {
    // 1. Fresh reserve: OK, entry reserved (no orig yet).
    void *orig = (void *)(uintptr_t)0xDEAD;
    assert(hk_inline_guard_reserve((uintptr_t)fn1, repA, 1, &orig) == HK_GUARD_OK);
    assert(orig == NULL);

    // 2. Same address + same replacement: DUP, saved original returned.
    void *saved = NULL;
    hk_inline_guard_update((uintptr_t)fn1, 0, repA);  // HK_OK stores the original
    assert(hk_inline_guard_reserve((uintptr_t)fn1, repA, 2, &saved) == HK_GUARD_DUP);
    assert(saved == repA);

    // 3. Same address, different replacement, different backend type: BLOCKED.
    assert(hk_inline_guard_reserve((uintptr_t)fn1, repB, 2, NULL) == HK_GUARD_BLOCKED);

    // 4. Same address, different replacement, SAME backend type: chained OK.
    assert(hk_inline_guard_reserve((uintptr_t)fn1, repB, 1, NULL) == HK_GUARD_OK);

    // 5. update(HK_ERR_NOT_SUPPORTED) releases the entry: a later different
    //    backend + different replacement succeeds.
    hk_inline_guard_update((uintptr_t)fn1, 2, NULL);  // NOT_SUPPORTED: wrote nothing
    assert(hk_inline_guard_reserve((uintptr_t)fn1, repB, 2, NULL) == HK_GUARD_OK);

    // 6. update(HK_ERR) taints: a later different-type different-replacement
    //    hook is still BLOCKED even though the replacement differs.
    hk_inline_guard_update((uintptr_t)fn1, 1, NULL);  // HK_ERR: possibly half-written
    assert(hk_inline_guard_reserve((uintptr_t)fn1, repC, 2, NULL) == HK_GUARD_BLOCKED);

    // 7. Unrelated address stays free throughout.
    assert(hk_inline_guard_reserve((uintptr_t)fn2, repA, 9, NULL) == HK_GUARD_OK);

    printf("test_inline_guard: all assertions passed\n");
    return 0;
}
