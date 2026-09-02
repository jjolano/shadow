#include <stdio.h>
#include <string.h>

#include "../src/ShadowCore.dylib/SHDWHookFallback.h"

int RunHookFallbackTests(void) {
    int failed = 0;
    hk_hook_result_t result;

#define CHECK(condition, name) do { \
    if(!(condition)) { \
        fprintf(stderr, "FAIL: hook fallback %s\n", name); \
        failed++; \
    } \
} while(0)

    memset(&result, 0, sizeof(result));
    result.mutation = HK_MUTATION_NONE;
    result.outcome = HK_OUTCOME_NO_ROUTE;
    CHECK(shdw_hook_result_refused_cleanly(&result), "no route");

    result.outcome = HK_OUTCOME_FAILED_SAFE;
    CHECK(shdw_hook_result_refused_cleanly(&result), "safe refusal");

    result.mutation = HK_MUTATION_PARTIAL;
    CHECK(!shdw_hook_result_refused_cleanly(&result), "partial mutation");

    result.mutation = HK_MUTATION_UNKNOWN;
    CHECK(!shdw_hook_result_refused_cleanly(&result), "unknown mutation");

    result.mutation = HK_MUTATION_NONE;
    result.outcome = HK_OUTCOME_ACTIVE;
    CHECK(!shdw_hook_result_refused_cleanly(&result), "active hook");

    return failed;
}

#if defined(SHDW_HOOK_FALLBACK_TEST_MAIN)
int main(void) {
    return RunHookFallbackTests();
}
#endif
