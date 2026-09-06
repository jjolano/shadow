// Host-runnable check for the anti-fishhook journal + repair core in
// src/ShadowCore.dylib/hooks/Universal/rebind_slots.h (pure C, no mach or
// Foundation, so it compiles and runs on the build host).
//
// Build and run:
//   cc -std=c99 -Wall -Wextra -o /tmp/shadow-rebind-test tests/verify-rebind-repair.c
//   /tmp/shadow-rebind-test
//
// What it simulates: a fishhook-style rebind writes replacement R into import
// slot S (note), swift-anti-fishhook writes the true address T back (direct
// store, bypassing the vm_protect guard), and the event-driven repair loop
// restores R.

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../src/ShadowCore.dylib/hooks/Universal/rebind_slots.h"

int main(void) {
    shdw_rebind_slots_t t;
    __builtin_memset(&t, 0, sizeof(t));

    // Fake import-slot cells (writable memory standing in for __DATA).
    uintptr_t cellA = 0, cellB = 0, cellC = 0;
    uintptr_t replA = 0x11111111u, replB = 0x22222222u;
    uintptr_t trueA = 0xAAAAAAAAu;

    // Note + healthy repair is a no-op.
    shdw_rebind_slots_note(&t, (uintptr_t)&cellA, sizeof(cellA), replA);
    shdw_rebind_slots_note(&t, (uintptr_t)&cellB, sizeof(cellB), replB);
    assert(t.count == 2);
    cellA = replA;
    cellB = replB;
    assert(shdw_rebind_slots_repair(&t, t.count) == 0);

    // Anti-fishhook undo of one slot: repair restores exactly that slot.
    cellA = trueA;
    assert(shdw_rebind_slots_repair(&t, t.count) == 1);
    assert(cellA == replA);
    assert(cellB == replB);
    assert(shdw_rebind_slots_repair(&t, t.count) == 0);

    // Re-noting the same slot refreshes the expectation (legit re-rebind).
    shdw_rebind_slots_note(&t, (uintptr_t)&cellA, sizeof(cellA), trueA);
    assert(t.count == 2);
    assert(shdw_rebind_slots_repair(&t, t.count) == 1); // cellA still replA
    assert(cellA == trueA);

    // Overlap predicate: the vm_protect guard's question.
    assert(shdw_rebind_slots_overlap(&t, t.count, (uintptr_t)&cellA, sizeof(cellA)) == 1);
    assert(shdw_rebind_slots_overlap(&t, t.count, (uintptr_t)&cellC, sizeof(cellC)) == 0);
    assert(shdw_rebind_slots_overlap(&t, t.count, 0, sizeof(cellA)) == 0);
    assert(shdw_rebind_slots_overlap(&t, 0, (uintptr_t)&cellA, sizeof(cellA)) == 0);

    // Unload prunes the image's slots: repair never touches them again.
    cellB = 0xBBBBBBBBu; // undone, but about to be unmapped
    shdw_rebind_slots_forget_range(&t, (uintptr_t)&cellB, (uintptr_t)&cellB + sizeof(cellB));
    assert(t.count == 1);
    assert(shdw_rebind_slots_repair(&t, t.count) == 0);
    assert(cellB == 0xBBBBBBBBu); // untouched
    assert(shdw_rebind_slots_overlap(&t, t.count, (uintptr_t)&cellB, sizeof(cellB)) == 0);

    // Forgetting a range that covers nothing changes nothing.
    shdw_rebind_slots_forget_range(&t, (uintptr_t)&cellC, (uintptr_t)&cellC + sizeof(cellC));
    assert(t.count == 1);
    shdw_rebind_slots_forget_range(&t, 0, 0);
    assert(t.count == 1);

    // Overflow latches instead of dropping silently.
    shdw_rebind_slots_t full;
    __builtin_memset(&full, 0, sizeof(full));
    static uintptr_t cells[SHDW_REBIND_SLOTS_MAX + 4];
    for(uint32_t i = 0; i < SHDW_REBIND_SLOTS_MAX + 4; i++) {
        cells[i] = 0;
        shdw_rebind_slots_note(&full, (uintptr_t)&cells[i], sizeof(cells[i]), replA);
    }
    assert(full.count == SHDW_REBIND_SLOTS_MAX);
    assert(full.overflowed == 1);

    printf("rebind-repair: ok\n");
    return 0;
}
