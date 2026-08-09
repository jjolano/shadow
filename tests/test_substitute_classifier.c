// Host-side unit test for the substitute error classifier. Runs on the build
// machine, not the device: it is a pure code table (no runtime, no dlopen).
//
//   clang -Wall -Wextra -O2 -x objective-c -Ivendor -IHeaders -Itests/fake_headers -D__APPLE__ \
//         -o /tmp/t tests/test_substitute_classifier.c Internal/HKSubstituteErrors.c && /tmp/t
//
// The classifier under test is the REAL production helper
// (Internal/HKSubstituteErrors.c), extracted from Backends/HKMSBackends.m as
// pure C so it compiles on the host. There is no mirror copy of the taxonomy
// table — if the production classification changes, this test changes with it
// or fails. The only duplication left is the trivial category->hookkit-status
// correspondence below (three rows, mirroring the wrapper in HKMSBackends.m);
// the taxonomy that actually decides those rows is the shared helper.
//
// The vendored libsubstitute header is included for real (through a fake
// __APPLE__ so its Mach-O sections compile on Linux, plus minimal stubs for
// its Mach-O and ObjC dependencies): every SUBSTITUTE_ERR_* constant in the
// table below is the vendored constant, not a hardcoded number, so the test
// stays correct if the header changes. Unknown/future codes are covered by
// the trailing garbage rows, which must fail closed to HK_ERR.

#include <stdint.h>
#include <mach-o/nlist.h>
#include <objc/runtime.h>

#include "substitute/substitute.h"

#include "HookKit/Compat.h"

#include "HKSubstituteErrors.h"

#include <assert.h>
#include <stdio.h>

// --- category -> hookkit status ---------------------------------------------
// Mirrors the three-row wrapper in Backends/HKMSBackends.m
// (substitute_error_to_status): OK stays HK_OK, capability misses become
// HK_ERR_NOT_SUPPORTED (nothing was written, callers may switch technique),
// everything else fails closed to HK_ERR. The decision table underneath is
// the real helper.
static hookkit_status_t substitute_error_to_status(int err) {
    switch(hk_substitute_err_classify(err)) {
        case HKSubErrOK:
            return HK_OK;

        case HKSubErrCapabilityMiss:
            return HK_ERR_NOT_SUPPORTED;

        default:
            return HK_ERR;
    }
}

// --- the exhaustive table ---------------------------------------------------
// One row per SUBSTITUTE_ERR_* constant from the vendored header (via the
// enumerators below, so new codes can only be added by someone also editing
// the classifier), plus SUBSTITUTE_OK and unknown/future values that must
// fail closed. Rows are `{ code, name, expected status }` so a failure prints
// which input broke.
static const struct {
    int code;
    const char *name;
    hookkit_status_t expected;
} kTable[] = {
    { SUBSTITUTE_OK, "SUBSTITUTE_OK", HK_OK },

    // Capability misses: the hook was NOT applied; callers may retry with a
    // different technique.
    { SUBSTITUTE_ERR_FUNC_TOO_SHORT, "SUBSTITUTE_ERR_FUNC_TOO_SHORT", HK_ERR_NOT_SUPPORTED },
    { SUBSTITUTE_ERR_FUNC_BAD_INSN_AT_START, "SUBSTITUTE_ERR_FUNC_BAD_INSN_AT_START", HK_ERR_NOT_SUPPORTED },
    { SUBSTITUTE_ERR_FUNC_CALLS_AT_START, "SUBSTITUTE_ERR_FUNC_CALLS_AT_START", HK_ERR_NOT_SUPPORTED },
    { SUBSTITUTE_ERR_FUNC_JUMPS_TO_START, "SUBSTITUTE_ERR_FUNC_JUMPS_TO_START", HK_ERR_NOT_SUPPORTED },
    { SUBSTITUTE_ERR_OUT_OF_RANGE, "SUBSTITUTE_ERR_OUT_OF_RANGE", HK_ERR_NOT_SUPPORTED },
    { SUBSTITUTE_ERR_NO_SUCH_SELECTOR, "SUBSTITUTE_ERR_NO_SUCH_SELECTOR", HK_ERR_NOT_SUPPORTED },

    // Terminal failures: the hook may already be applied, so it must never be
    // retried. Also covers _SUBSTITUTE_CURRENT_MAX_ERR_PLUS_ONE (13).
    { SUBSTITUTE_ERR_OOM, "SUBSTITUTE_ERR_OOM", HK_ERR },
    { SUBSTITUTE_ERR_VM, "SUBSTITUTE_ERR_VM", HK_ERR },
    { SUBSTITUTE_ERR_NOT_ON_MAIN_THREAD, "SUBSTITUTE_ERR_NOT_ON_MAIN_THREAD", HK_ERR },
    { SUBSTITUTE_ERR_UNEXPECTED_PC_ON_OTHER_THREAD, "SUBSTITUTE_ERR_UNEXPECTED_PC_ON_OTHER_THREAD", HK_ERR },
    { SUBSTITUTE_ERR_UNKNOWN_RELOCATION_TYPE, "SUBSTITUTE_ERR_UNKNOWN_RELOCATION_TYPE", HK_ERR },
    { SUBSTITUTE_ERR_ADJUSTING_THREADS, "SUBSTITUTE_ERR_ADJUSTING_THREADS", HK_ERR },

    // Unknown / future codes from a newer installed libsubstitute than the
    // vendored header: the default must fail closed.
    { 13, "13 (max-err sentinel)", HK_ERR },
    { -1, "-1", HK_ERR },
    { 999, "999", HK_ERR },
    { 0x7FFFFFFF, "0x7FFFFFFF", HK_ERR },
};

// --- retryable (GOT/PLT interpose eligibility) ------------------------------
// The interpose fallback in HKMSBackends.m fires only for the five function
// capability-miss codes. These MUST be retryable; everything else — including
// NO_SUCH_SELECTOR (a message-hook miss, not a function-shape miss) and every
// terminal code — must NOT be retried via interpose.
static const struct {
    int code;
    const char *name;
    bool retryable;
} kRetryTable[] = {
    { SUBSTITUTE_OK, "SUBSTITUTE_OK", false },
    { SUBSTITUTE_ERR_FUNC_TOO_SHORT, "SUBSTITUTE_ERR_FUNC_TOO_SHORT", true },
    { SUBSTITUTE_ERR_FUNC_BAD_INSN_AT_START, "SUBSTITUTE_ERR_FUNC_BAD_INSN_AT_START", true },
    { SUBSTITUTE_ERR_FUNC_CALLS_AT_START, "SUBSTITUTE_ERR_FUNC_CALLS_AT_START", true },
    { SUBSTITUTE_ERR_FUNC_JUMPS_TO_START, "SUBSTITUTE_ERR_FUNC_JUMPS_TO_START", true },
    { SUBSTITUTE_ERR_OUT_OF_RANGE, "SUBSTITUTE_ERR_OUT_OF_RANGE", true },
    { SUBSTITUTE_ERR_NO_SUCH_SELECTOR, "SUBSTITUTE_ERR_NO_SUCH_SELECTOR", false },
    { SUBSTITUTE_ERR_OOM, "SUBSTITUTE_ERR_OOM", false },
    { SUBSTITUTE_ERR_VM, "SUBSTITUTE_ERR_VM", false },
    { SUBSTITUTE_ERR_NOT_ON_MAIN_THREAD, "SUBSTITUTE_ERR_NOT_ON_MAIN_THREAD", false },
    { SUBSTITUTE_ERR_UNEXPECTED_PC_ON_OTHER_THREAD, "SUBSTITUTE_ERR_UNEXPECTED_PC_ON_OTHER_THREAD", false },
    { SUBSTITUTE_ERR_UNKNOWN_RELOCATION_TYPE, "SUBSTITUTE_ERR_UNKNOWN_RELOCATION_TYPE", false },
    { SUBSTITUTE_ERR_ADJUSTING_THREADS, "SUBSTITUTE_ERR_ADJUSTING_THREADS", false },
    { 13, "13 (max-err sentinel)", false },
    { -1, "-1", false },
    { 999, "999", false },
    { 0x7FFFFFFF, "0x7FFFFFFF", false },
};

// --- category cross-check ---------------------------------------------------
// The classify() categories must agree with the status mapping (so the
// interpose fallback, which keys off the same taxonomy, can never diverge
// from the inline-path status report).
static void check_category(int err, hk_substitute_err_t expected) {
    hk_substitute_err_t got = hk_substitute_err_classify(err);
    assert(got == expected);
}

int main(void) {
    // Every row must use an enumerator from the vendored header, not a
    // hardcoded number.
    assert(SUBSTITUTE_OK == 0);
    assert(SUBSTITUTE_ERR_FUNC_TOO_SHORT == 1);
    assert(SUBSTITUTE_ERR_FUNC_BAD_INSN_AT_START == 2);
    assert(SUBSTITUTE_ERR_FUNC_CALLS_AT_START == 3);
    assert(SUBSTITUTE_ERR_FUNC_JUMPS_TO_START == 4);
    assert(SUBSTITUTE_ERR_OOM == 5);
    assert(SUBSTITUTE_ERR_VM == 6);
    assert(SUBSTITUTE_ERR_NOT_ON_MAIN_THREAD == 7);
    assert(SUBSTITUTE_ERR_UNEXPECTED_PC_ON_OTHER_THREAD == 8);
    assert(SUBSTITUTE_ERR_OUT_OF_RANGE == 9);
    assert(SUBSTITUTE_ERR_UNKNOWN_RELOCATION_TYPE == 10);
    assert(SUBSTITUTE_ERR_NO_SUCH_SELECTOR == 11);
    assert(SUBSTITUTE_ERR_ADJUSTING_THREADS == 12);

    for(size_t i = 0; i < sizeof(kTable) / sizeof(kTable[0]); i++) {
        assert(substitute_error_to_status(kTable[i].code) == kTable[i].expected);
        printf("  %-45s -> %s\n", kTable[i].name,
               kTable[i].expected == HK_OK ? "HK_OK"
               : kTable[i].expected == HK_ERR_NOT_SUPPORTED ? "HK_ERR_NOT_SUPPORTED"
               : "HK_ERR");
    }

    size_t nStatus = sizeof(kTable) / sizeof(kTable[0]);

    for(size_t i = 0; i < sizeof(kRetryTable) / sizeof(kRetryTable[0]); i++) {
        assert(hk_substitute_err_is_retryable(kRetryTable[i].code) == kRetryTable[i].retryable);
        printf("  %-45s -> %s\n", kRetryTable[i].name,
               kRetryTable[i].retryable ? "retryable" : "not retryable");
    }

    size_t nRetry = sizeof(kRetryTable) / sizeof(kRetryTable[0]);

    // Categories: OK, capability miss, or terminal.
    check_category(SUBSTITUTE_OK, HKSubErrOK);
    check_category(SUBSTITUTE_ERR_FUNC_TOO_SHORT, HKSubErrCapabilityMiss);
    check_category(SUBSTITUTE_ERR_FUNC_BAD_INSN_AT_START, HKSubErrCapabilityMiss);
    check_category(SUBSTITUTE_ERR_FUNC_CALLS_AT_START, HKSubErrCapabilityMiss);
    check_category(SUBSTITUTE_ERR_FUNC_JUMPS_TO_START, HKSubErrCapabilityMiss);
    check_category(SUBSTITUTE_ERR_OUT_OF_RANGE, HKSubErrCapabilityMiss);
    check_category(SUBSTITUTE_ERR_NO_SUCH_SELECTOR, HKSubErrCapabilityMiss);
    check_category(SUBSTITUTE_ERR_OOM, HKSubErrTerminal);
    check_category(SUBSTITUTE_ERR_VM, HKSubErrTerminal);
    check_category(SUBSTITUTE_ERR_NOT_ON_MAIN_THREAD, HKSubErrTerminal);
    check_category(SUBSTITUTE_ERR_UNEXPECTED_PC_ON_OTHER_THREAD, HKSubErrTerminal);
    check_category(SUBSTITUTE_ERR_UNKNOWN_RELOCATION_TYPE, HKSubErrTerminal);
    check_category(SUBSTITUTE_ERR_ADJUSTING_THREADS, HKSubErrTerminal);
    check_category(13, HKSubErrTerminal);
    check_category(-1, HKSubErrTerminal);
    check_category(999, HKSubErrTerminal);
    check_category(0x7FFFFFFF, HKSubErrTerminal);

    printf("all %zu substitute error classifier tests passed\n",
           nStatus + nRetry);
    return 0;
}
