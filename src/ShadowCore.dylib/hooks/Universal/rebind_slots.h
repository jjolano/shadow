#ifndef shadow_hooks_rebind_slots_h
#define shadow_hooks_rebind_slots_h

// Import-slot journal + check-then-store repair core (anti-fishhook).
//
// Split out of SHDWHookSession.m so the host test harness can exercise it:
// SHDWHookSession.m pulls HookKit/ObjC and only builds for iOS, while
// everything here is plain C over <stdint.h>/<stddef.h>. The process-global
// instance, the HookKit artifact ingestion that fills it, and the rebind-spec
// journal for new-image replay live in SHDWHookSession.m / RebindRepair.x,
// which wrap this with the atomics.
//
// Model: every fishhook-style rebind Shadow installs writes a replacement
// pointer into one or more import slots (GOT / lazy-pointer cells in the
// caller images' __DATA). swift-anti-fishhook undoes exactly those stores —
// either through fishhook itself (blocked by the vm_protect guard in
// ImportSlotProtection.x) or through a direct store (not blockable). The
// repair loop re-reads each journaled slot and stores the expected
// replacement back when it differs. Pointer-size aligned loads/stores are
// single-copy atomic on arm64, so repair is safe against a concurrent
// attacker store: worst case the next event repairs again.

#include <stddef.h>
#include <stdint.h>

#define SHDW_REBIND_SLOTS_MAX 2048

typedef struct {
    uintptr_t start;    // slot cell address (inclusive)
    uintptr_t end;      // exclusive (start + cell size)
    uintptr_t expected; // replacement pointer the cell must hold
} shdw_rebind_slot_t;

typedef struct {
    shdw_rebind_slot_t slot[SHDW_REBIND_SLOTS_MAX];
    uint32_t count;
    // Latched on the first dropped note and logged once by the installer;
    // a dropped slot is unguarded AND unrepaired, so silence here would be
    // a hole, not thrift.
    uint32_t overflowed;
} shdw_rebind_slots_t;

// Record one slot. Re-noting the same (start,end) refreshes the expected
// value instead of duplicating the entry (a re-rebind legitimately changes
// what the slot must hold).
static inline void shdw_rebind_slots_note(shdw_rebind_slots_t *t,
                                          uintptr_t start, size_t size,
                                          uintptr_t expected) {
    if(!t || !start || !expected) {
        return;
    }
    if(!size) {
        size = sizeof(void *);
    }
    uintptr_t end = size > UINTPTR_MAX - start ? UINTPTR_MAX : start + size;
    for(uint32_t i = 0; i < t->count; i++) {
        if(t->slot[i].start == start && t->slot[i].end == end) {
            t->slot[i].expected = expected;
            return;
        }
    }
    if(t->count >= SHDW_REBIND_SLOTS_MAX) {
        t->overflowed = 1;
        return;
    }
    t->slot[t->count++] = (shdw_rebind_slot_t){ start, end, expected };
}

// Drop every entry fully inside [base, end): the image owning those slots
// was unmapped and the addresses may be reused. Repair must never
// dereference a stale slot (unmapped read = crash; reused mapping = wild
// store into another image's data).
static inline void shdw_rebind_slots_forget_range(shdw_rebind_slots_t *t,
                                                  uintptr_t base,
                                                  uintptr_t end) {
    if(!t || end <= base) {
        return;
    }
    uint32_t kept = 0;
    for(uint32_t i = 0; i < t->count; i++) {
        if(t->slot[i].start >= base && t->slot[i].end <= end) {
            continue;
        }
        t->slot[kept++] = t->slot[i];
    }
    t->count = kept;
}

// vm_protect-guard predicate: does [address, address+size) touch a
// journaled slot?
static inline int shdw_rebind_slots_overlap(const shdw_rebind_slots_t *t,
                                            uint32_t count,
                                            uintptr_t address, size_t size) {
    if(!t || !address || !size) {
        return 0;
    }
    uintptr_t end = size > UINTPTR_MAX - address ? UINTPTR_MAX : address + size;
    if(count > t->count) {
        count = t->count;
    }
    for(uint32_t i = 0; i < count; i++) {
        if(address < t->slot[i].end && end > t->slot[i].start) {
            return 1;
        }
    }
    return 0;
}

// Repair pass: store the expected replacement into every slot whose live
// value differs. Returns the number of slots repaired. Live cells are
// touched with single-copy atomic access; the table itself must be stable
// across the call (the caller holds the count snapshot discipline its
// atomics give it: acquire-load count, repair, entries are never mutated
// in place except the expected refresh above).
static inline uint32_t shdw_rebind_slots_repair(const shdw_rebind_slots_t *t,
                                                uint32_t count) {
    if(!t) {
        return 0;
    }
    if(count > t->count) {
        count = t->count;
    }
    uint32_t repaired = 0;
    for(uint32_t i = 0; i < count; i++) {
        uintptr_t start = t->slot[i].start;
        uintptr_t expected = t->slot[i].expected;
        if(!start || !expected) {
            continue;
        }
        uintptr_t *cell = (uintptr_t *)(void *)start;
        if(__atomic_load_n(cell, __ATOMIC_RELAXED) != expected) {
            __atomic_store_n(cell, expected, __ATOMIC_RELAXED);
            repaired++;
        }
    }
    return repaired;
}

#endif
