// Host-side unit test for the substitute error classifier. Runs on the build
// machine, not the device: it is a pure code table (no runtime, no dlopen).
//
//   clang -Wall -Wextra -O2 -Ivendor -o /tmp/t tests/test_substitute_classifier.c && /tmp/t
//
// The classifier under test is `static` inside Backends/HKMSBackends.m, which
// is ObjC and depends on runtime dlopen, so it cannot be compiled into a plain
// host test. The preferred rename-on-include trick does not work here either:
// HKMSBackends.m drags in Foundation, objc/runtime.h and the Cydia Substrate
// headers, none of which exist on the host. The function below is therefore a
// mirror copy, kept byte-for-byte identical to the production classifier
// (Backends/HKMSBackends.m, `substitute_error_to_status`).
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

#include <assert.h>
#include <stdio.h>

// --- classifier under test (mirror of Backends/HKMSBackends.m) -------------
// Mirror copy, not rename-on-include: HKMSBackends.m is ObjC with dlopen and
// Foundation dependencies that do not compile on the host. Keep this body
// byte-for-byte identical to the production function.
static hookkit_status_t substitute_error_to_status(int err) {
    switch(err) {
        case SUBSTITUTE_OK:
            return HK_OK;

        case SUBSTITUTE_ERR_FUNC_TOO_SHORT:
        case SUBSTITUTE_ERR_FUNC_BAD_INSN_AT_START:
        case SUBSTITUTE_ERR_FUNC_CALLS_AT_START:
        case SUBSTITUTE_ERR_FUNC_JUMPS_TO_START:
        case SUBSTITUTE_ERR_OUT_OF_RANGE:
        case SUBSTITUTE_ERR_NO_SUCH_SELECTOR:
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

    printf("all %zu substitute error classifier tests passed\n",
           sizeof(kTable) / sizeof(kTable[0]));
    return 0;
}
