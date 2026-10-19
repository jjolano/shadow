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
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

#include "../src/ShadowCore.dylib/hooks/Universal/rebind_slots.h"

#define STRESS_THREADS 8
#define STRESS_ITERS 25000

static shdw_rebind_slots_t gStress;
static pthread_mutex_t gStressLock = PTHREAD_MUTEX_INITIALIZER;
static uintptr_t gStressCell[STRESS_THREADS];
static uintptr_t gStressRepl[STRESS_THREADS];

static void *stress_worker(void *arg) {
    long id = (long)arg;

    for (int i = 0; i < STRESS_ITERS; i++) {
        long victim = (id + 1) % STRESS_THREADS;

        pthread_mutex_lock(&gStressLock);
        shdw_rebind_slots_note(&gStress, (uintptr_t)&gStressCell[id],
                               sizeof(uintptr_t), gStressRepl[id]);
        (void)shdw_rebind_slots_repair(&gStress, gStress.count);
        shdw_rebind_slots_forget_range(
            &gStress, (uintptr_t)&gStressCell[victim],
            (uintptr_t)&gStressCell[victim] + sizeof(uintptr_t));
        (void)shdw_rebind_slots_repair(&gStress, gStress.count);
        pthread_mutex_unlock(&gStressLock);
    }

    return NULL;
}

int main(void) {
    shdw_rebind_slots_t t;
    __builtin_memset(&t, 0, sizeof(t));

    for (int i = 0; i < STRESS_THREADS; i++) {
        gStressCell[i] = 0;
        gStressRepl[i] = 0x90000000u + (uintptr_t)i;
    }

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

    // Unload prunes the image's slots. Retirement must NOT move entries or
    // lower the count: a repair that took its count snapshot before the unload
    // still walks the same indices. The compacting version this replaces
    // shifted the live entry down, lowered count, and left a stale copy of the
    // dropped entry in the freed slot — so the stale-count repair below stored
    // straight into the unmapped slot.
    uint32_t stale_count = t.count;
    cellB = 0xBBBBBBBBu; // undone, but about to be unmapped
    shdw_rebind_slots_forget_range(&t, (uintptr_t)&cellB, (uintptr_t)&cellB + sizeof(cellB));
    assert(t.count == stale_count);
    assert(shdw_rebind_slots_repair(&t, stale_count) == 0);
    assert(cellB == 0xBBBBBBBBu); // untouched, no stale-copy store
    assert(shdw_rebind_slots_overlap(&t, stale_count, (uintptr_t)&cellB, sizeof(cellB)) == 0);
    assert(shdw_rebind_slots_overlap(&t, t.count, (uintptr_t)&cellB, sizeof(cellB)) == 0);

    // The retired entry is reused rather than leaked: a later slot takes the
    // tombstone, and the table does not grow.
    uintptr_t cellD = 0;
    uintptr_t replD = 0x44444444u;
    shdw_rebind_slots_note(&t, (uintptr_t)&cellD, sizeof(cellD), replD);
    assert(t.count == stale_count);
    cellD = 0;
    assert(shdw_rebind_slots_repair(&t, t.count) == 1);
    assert(cellD == replD);

    // Forgetting a range that covers nothing changes nothing.
    uint32_t count_before = t.count;
    shdw_rebind_slots_forget_range(&t, (uintptr_t)&cellC, (uintptr_t)&cellC + sizeof(cellC));
    assert(t.count == count_before);
    assert(shdw_rebind_slots_repair(&t, t.count) == 0);
    shdw_rebind_slots_forget_range(&t, 0, 0);
    assert(t.count == count_before);

    // Retire-then-reuse must never write the NEW entry's replacement into the
    // OLD cell. The production wrappers serialize note/forget/repair for exactly
    // this reason: a repair that loaded the old entry's start and then the new
    // entry's expected would store another symbol's pointer into a live import
    // slot (calls jumping into the wrong hook, not a crash).
    {
        shdw_rebind_slots_t r;
        __builtin_memset(&r, 0, sizeof(r));

        uintptr_t oldCell = 0, newCell = 0;
        uintptr_t oldRepl = 0xAAAA0001u, newRepl = 0xBBBB0002u;

        shdw_rebind_slots_note(&r, (uintptr_t)&oldCell, sizeof(oldCell), oldRepl);
        shdw_rebind_slots_forget_range(&r, (uintptr_t)&oldCell,
                                       (uintptr_t)&oldCell + sizeof(oldCell));
        shdw_rebind_slots_note(&r, (uintptr_t)&newCell, sizeof(newCell), newRepl);

        oldCell = oldRepl;   // the retired slot still holds its old value
        newCell = 0;

        assert(shdw_rebind_slots_repair(&r, r.count) == 1);
        assert(newCell == newRepl);   // the live slot got its own pointer
        assert(oldCell == oldRepl);   // the retired cell was not touched
    }

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

    // Concurrent note/forget/repair under the same serialization the production
    // wrappers apply (one lock over every table access). Each worker owns one
    // cell; workers retire each other's cells the way an image unload would, so
    // a mis-paired start/expected store would leave a FOREIGN replacement in a
    // cell — the invariant checked after the joins. The table requires caller
    // serialization (rebind_slots.h), which is what this lock mirrors: the test
    // covers retire/reuse/repair interleavings under that discipline.
    {
        pthread_t threads[STRESS_THREADS];

        for (long i = 0; i < STRESS_THREADS; i++)
            assert(pthread_create(&threads[i], NULL, stress_worker, (void *)i) == 0);
        for (int i = 0; i < STRESS_THREADS; i++)
            assert(pthread_join(threads[i], NULL) == 0);

        for (int i = 0; i < STRESS_THREADS; i++)
            assert(gStressCell[i] == 0 || gStressCell[i] == gStressRepl[i]);
        assert(gStress.count <= SHDW_REBIND_SLOTS_MAX);
    }

    printf("rebind-repair: ok\n");
    return 0;
}
