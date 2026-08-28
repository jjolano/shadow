#ifndef shdw_hook_fallback_h
#define shdw_hook_fallback_h

#include <HookKit/HookKitResults.h>

static inline bool shdw_hook_result_refused_cleanly(
    const hk_hook_result_t* result) {
    return result && result->mutation == HK_MUTATION_NONE &&
        (result->outcome == HK_OUTCOME_NO_ROUTE ||
         result->outcome == HK_OUTCOME_FAILED_SAFE);
}

#endif
