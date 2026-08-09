// HookKit private header: Substitute error classification, extracted into a
// pure-C helper so the host-side unit test (tests/test_substitute_classifier.c)
// compiles the REAL production code instead of a mirror copy.
//
// Lives under Internal/ at the project root, NOT under Headers/, so it is
// never installed into the public Headers/ tree. Pure C: no Objective-C, no
// runtime dlopen — only the vendored libsubstitute enum values.
//
// The status mapping is shared by both the inline hook path (via
// substitute_error_to_status) and the GOT/PLT interpose fallback, so the two
// can never diverge.
#ifndef hookkit_substitute_errors_h
#define hookkit_substitute_errors_h

#include <stdbool.h>

#include "substitute/substitute.h"

typedef enum {
    // No error.
    HKSubErrOK = 0,
    // Capability miss: the hook was NOT applied — the function's shape or the
    // selector's absence make this technique unusable (HK_ERR_NOT_SUPPORTED
    // so callers can switch hooking techniques). The five function codes are
    // also the only ones the GOT/PLT interpose fallback retries.
    HKSubErrCapabilityMiss = 1,
    // Terminal failure: the hook may already be applied (OOM, VM,
    // NOT_ON_MAIN_THREAD, UNEXPECTED_PC_ON_OTHER_THREAD [the hooks were
    // otherwise completed], ADJUSTING_THREADS), so it must never be retried.
    HKSubErrTerminal = 2,
} hk_substitute_err_t;

// Maps a native libsubstitute error code to its category. Pure: no state,
// just the code table. Fails closed to HKSubErrTerminal for any unknown or
// future code from a newer installed libsubstitute than the vendored header.
hk_substitute_err_t hk_substitute_err_classify(int err);

// True when the code is one of the five function capability misses that mean
// substitute did not write anything, so GOT/PLT interposition is safe to
// retry. Everything else (including NO_SUCH_SELECTOR, which is a message-hook
// miss) must NOT be retried via interpose.
bool hk_substitute_err_is_retryable(int err);

#endif
