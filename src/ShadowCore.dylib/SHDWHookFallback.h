#ifndef shdw_hook_fallback_h
#define shdw_hook_fallback_h

#include <HookKit/HookKitResults.h>

// ponytail: delegate to canonical HookKit helper, no duplicate logic
static inline bool shdw_hook_result_refused_cleanly(
    const hk_hook_result_t* result) {
    return hk_hook_result_refused_cleanly(result);
}

#endif
