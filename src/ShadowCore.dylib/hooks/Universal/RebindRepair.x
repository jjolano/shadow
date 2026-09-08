#import "UniversalHooks.h"
#import "../HookCoordinator.h"

#include <mach-o/dyld.h>
#include <string.h>
#include <stdlib.h>

// Rebind-spec journal + event-driven repair (anti-fishhook).
//
// Two journals work together:
//   * the SLOT journal (SHDWHookSession.m, rebind_slots.h core) records every
//     import-slot address a rebind wrote, with the expected replacement.
//     Repair is check-then-store — no HookKit involvement, so it cannot hit
//     the "repeat request invalidates the plan" hazard and needs no session.
//   * this SPEC journal records every (symbol, replacement) pair installers
//     requested. It exists for late-loaded images: a global rebind only
//     covers imports bound at install time, so a detector framework dlopen'd
//     afterwards gets a scoped HookKit replay of the full journal.
//
// Both journals only grow on installer paths. Repair replays use the
// no-journal HookKit variant, so an image event never feeds the journal it
// is repairing (75 specs x N images would otherwise explode it).
//
// Triggers (event-only, no timer): dyld add-image (slots sync, image replay
// async on main when a detector is engaged), detector escalation entry
// (slots sync), vm_protect-guard deny (trip + coalesced async slots repair).

#define SHDW_REBIND_SPECS_MAX 320

typedef struct {
    char* name;
    void* replacement;
    // Caller-owned original cell, or NULL. Must be process-lifetime: replay
    // dereferences it on later image loads, after the installer returned.
    void** originalCell;
} shdw_rebind_spec_t;

static shdw_rebind_spec_t gSHDWRebindSpecs[SHDW_REBIND_SPECS_MAX];
static uint32_t gSHDWRebindSpecCount;
static uint32_t gSHDWRebindSpecOverflowed;

void SHDWRebindJournalNote(const char* symbolName, void* replacement, void** originalCell) {
    if(!symbolName || !symbolName[0] || !replacement) {
        return;
    }
    uint32_t count = __atomic_load_n(&gSHDWRebindSpecCount, __ATOMIC_ACQUIRE);
    for(uint32_t i = 0; i < count; i++) {
        if(gSHDWRebindSpecs[i].replacement == replacement &&
           strcmp(gSHDWRebindSpecs[i].name, symbolName) == 0) {
            return;
        }
    }
    if(count >= SHDW_REBIND_SPECS_MAX) {
        if(!__atomic_exchange_n(&gSHDWRebindSpecOverflowed, 1, __ATOMIC_ACQ_REL)) {
            NSLog(@"[Shadow] rebind spec journal full (%u) — new-image replay will miss %s",
                  count, symbolName);
        }
        return;
    }
    char* copy = strdup(symbolName);
    if(!copy) {
        return;
    }
    gSHDWRebindSpecs[count] = (shdw_rebind_spec_t){ copy, replacement, originalCell };
    __atomic_store_n(&gSHDWRebindSpecCount, count + 1, __ATOMIC_RELEASE);
}

// Scoped replay of one journal entry. Failures are routine (the image does
// not import the symbol) and stay silent; the global verify pass already
// covers install-time failures. When no install has established an original,
// the caller's cell is passed so this first import captures its predecessor;
// a cell that already holds a live original is left alone.
static void shdw_rebind_replay_one(SHDWHookSession* session,
                                   const shdw_rebind_spec_t* spec,
                                   const void* imageHeader) {
    NSString* name = [NSString stringWithUTF8String:spec->name];
    if(!name) {
        return;
    }
    void** cell = spec->originalCell;
    [session hookRebindSymbol:name
              withReplacement:spec->replacement
                     outOldPtr:(cell && *cell == NULL) ? cell : NULL
                 inCallerImage:imageHeader
                       journal:NO];
}

// Exported (like the header declares): late-image validation and the
// detector-gated loader path both resolve it from outside this image.
__attribute__((visibility("default")))
void SHDWRebindRepairImage(SHDWHookSession* session, const void* imageHeader) {
    if(!session || !imageHeader) {
        return;
    }
    uint32_t count = __atomic_load_n(&gSHDWRebindSpecCount, __ATOMIC_ACQUIRE);
    // Pass 1: the vm_protect import-slot guard first, so the remaining
    // replay is itself protected against a concurrent unhook. Pass 2:
    // everything else. (The guard is one symbol; the string compare is free
    // next to a HookKit commit.)
    for(uint32_t pass = 0; pass < 2; pass++) {
        for(uint32_t i = 0; i < count; i++) {
            BOOL isGuard = strcmp(gSHDWRebindSpecs[i].name, "vm_protect") == 0;
            if((pass == 0) != isGuard) {
                continue;
            }
            shdw_rebind_replay_one(session, &gSHDWRebindSpecs[i], imageHeader);
        }
    }
}

static uint32_t gSHDWRepairPending;

void SHDWRequestRebindRepair(void) {
    // Coalesced: at most one repair block queued. Runs on main, like the
    // detector escalation, so it never executes on a hook's stack or inside
    // the coordinator's lifecycle queue (whose re-entrancy guard would eat
    // a nested install).
    if(__atomic_exchange_n(&gSHDWRepairPending, 1, __ATOMIC_ACQ_REL)) {
        return;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        __atomic_store_n(&gSHDWRepairPending, 0, __ATOMIC_RELEASE);
        SHDWRebindRepairSlots();
    });
}

void SHDWRequestRebindRepairImage(const void* imageHeader) {
    if(!imageHeader) {
        return;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        // The image may have unloaded while queued; HookKit on a stale
        // EXACT_HEADER is at best a refusal, so re-resolve first.
        BOOL stillMapped = NO;
        uint32_t n = _dyld_image_count();
        for(uint32_t i = 0; i < n; i++) {
            if(_dyld_get_image_header(i) == (const struct mach_header*)imageHeader) {
                stillMapped = YES;
                break;
            }
        }
        if(!stillMapped) {
            return;
        }
        SHDWHookSession* session = [SHDWHookCoordinator shdw_sharedHookSession];
        SHDWRebindRepairImage(session, imageHeader);
    });
}
