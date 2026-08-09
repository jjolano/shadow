#include "HKInlineGuard.h"

#include <pthread.h>
#include <stdio.h>

// Fixed-size entry table under one mutex; linear scan. The guard exists to
// prevent double-patching of one prologue, which is a live-hook-count concern:
// ponytail: 64 live inline hooks is the ceiling — the few dozen real
// consumers never approach it; a hash map is the upgrade if >64 live inline
// hooks per process ever shows up.

typedef struct {
    uintptr_t addr;
    void *replacement;
    void *orig;
    int type;
    bool tainted;
    bool used;
} hk_guard_entry_t;

#define HK_GUARD_MAX_ENTRIES 64

static hk_guard_entry_t g_entries[HK_GUARD_MAX_ENTRIES];
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

hk_guard_result_t hk_inline_guard_reserve(uintptr_t address, void *replacement, int backendType, void **outOrig) {
    hk_guard_result_t result = HK_GUARD_OK;

    pthread_mutex_lock(&g_mutex);

    for(size_t i = 0; i < HK_GUARD_MAX_ENTRIES; i++) {
        if(!g_entries[i].used || g_entries[i].addr != address) {
            continue;
        }

        if(g_entries[i].tainted) {
            // The prologue may be half-written; only an identical re-hook is
            // safe. Anything else would stack on unknown bytes.
            if(g_entries[i].replacement == replacement) {
                if(outOrig) {
                    *outOrig = g_entries[i].orig;
                }

                result = HK_GUARD_DUP;
            } else {
                result = HK_GUARD_BLOCKED;
            }

            goto unlock;
        }

        if(g_entries[i].replacement == replacement) {
            // Idempotent re-hook: same address, same replacement.
            if(outOrig) {
                *outOrig = g_entries[i].orig;
            }

            result = HK_GUARD_DUP;
            goto unlock;
        }

        if(g_entries[i].type == backendType) {
            // Same backend type, different replacement: the provider itself
            // is chaining on this address — allow it.
            printf("[HKInlineGuard] note: chaining inline hook on %p via backend type %d\n", (void *)address, backendType);
            result = HK_GUARD_OK;
            goto unlock;
        }

        // Different backend type + different replacement: a second inline
        // writer would double-patch this prologue.
        result = HK_GUARD_BLOCKED;
        goto unlock;
    }

    for(size_t i = 0; i < HK_GUARD_MAX_ENTRIES; i++) {
        if(!g_entries[i].used) {
            g_entries[i].addr = address;
            g_entries[i].replacement = replacement;
            g_entries[i].orig = NULL;
            g_entries[i].type = backendType;
            g_entries[i].tainted = false;
            g_entries[i].used = true;

            if(outOrig) {
                *outOrig = NULL;    // no original saved yet — update() fills it after the hook lands
            }

            break;
        }
    }

unlock:
    pthread_mutex_unlock(&g_mutex);
    return result;
}

void hk_inline_guard_update(uintptr_t address, int status, void *origValue) {
    pthread_mutex_lock(&g_mutex);

    for(size_t i = 0; i < HK_GUARD_MAX_ENTRIES; i++) {
        if(!g_entries[i].used || g_entries[i].addr != address) {
            continue;
        }

        if(status == 0) {
            // HK_OK: the backend wrote the hook; the saved original is the
            // one future same-replacement re-hooks should return.
            g_entries[i].orig = origValue;
        } else if(status == 1) {
            // HK_ERR: the backend failed mid-flight — the prologue MAY be
            // half-written. Keep the entry and mark it tainted so a later
            // DIFFERENT hook on this address still blocks (it would stack on
            // whatever is there now).
            g_entries[i].tainted = true;
        } else if(status == 2) {
            // HK_ERR_NOT_SUPPORTED: the backend wrote nothing — release the
            // entry so a later hook can take the address.
            g_entries[i].used = false;
        }

        break;
    }

    pthread_mutex_unlock(&g_mutex);
}
