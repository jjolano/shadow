// Pure-C implementation of the Substitute error taxonomy. Compiled into the
// framework via HookKit_FILES and into the host-side unit test directly, so
// the test exercises the REAL production code. No Objective-C, no dlopen.
#include "HKSubstituteErrors.h"

hk_substitute_err_t hk_substitute_err_classify(int err) {
    switch(err) {
        case SUBSTITUTE_OK:
            return HKSubErrOK;

        // Capability misses: the hook was NOT applied — the function's shape
        // or the selector's absence make this technique unusable, which is
        // what HK_ERR_NOT_SUPPORTED reports so callers can switch hooking
        // techniques.
        case SUBSTITUTE_ERR_FUNC_TOO_SHORT:
        case SUBSTITUTE_ERR_FUNC_BAD_INSN_AT_START:
        case SUBSTITUTE_ERR_FUNC_CALLS_AT_START:
        case SUBSTITUTE_ERR_FUNC_JUMPS_TO_START:
        case SUBSTITUTE_ERR_OUT_OF_RANGE:
        case SUBSTITUTE_ERR_NO_SUCH_SELECTOR:
            return HKSubErrCapabilityMiss;

        // Everything else (OOM, VM, NOT_ON_MAIN_THREAD,
        // UNEXPECTED_PC_ON_OTHER_THREAD [the hooks were otherwise completed],
        // ADJUSTING_THREADS, or any unknown or future code from a newer
        // installed libsubstitute than the vendored header) is terminal: the
        // hook may already be applied, so it must never be retried. The
        // default fails closed to HKSubErrTerminal.
        default:
            return HKSubErrTerminal;
    }
}

bool hk_substitute_err_is_retryable(int err) {
    switch(err) {
        // The GOT/PLT interpose fallback fires ONLY for the five function
        // capability-miss codes: substitute reported it could not patch the
        // function, so nothing was written and interposing is safe. Any other
        // code means the hook may already be applied — retrying with
        // interposition could double-hook. NO_SUCH_SELECTOR is deliberately
        // excluded: it is a message-hook miss, not a function-shape miss.
        case SUBSTITUTE_ERR_FUNC_TOO_SHORT:
        case SUBSTITUTE_ERR_FUNC_BAD_INSN_AT_START:
        case SUBSTITUTE_ERR_FUNC_CALLS_AT_START:
        case SUBSTITUTE_ERR_FUNC_JUMPS_TO_START:
        case SUBSTITUTE_ERR_OUT_OF_RANGE:
            return true;

        default:
            return false;
    }
}
