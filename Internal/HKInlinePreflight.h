// Shared fixed-window ARM64 prologue validator for the Dobby and litehook
// inline backends. Both vendors overwrite a fixed window of the target's
// prologue (Dobby 16 bytes, litehook 20 bytes), and both refuse — before any
// write — a target whose window would be unsafe to clobber. The Dobby and
// litehook hook paths and their public preflightFunction: routes call the
// same validator with the same overwrite size, so preflight agrees exactly
// with execution.
//
// The validator is side-effect-free: it reads only the overwrite window and
// never writes, so a reject leaves the target untouched. It also owns pointer
// canonicalization (PAC strip on arm64e) before inspecting, so the hook paths
// and preflight inspect the same raw address.
#ifndef hookkit_inline_preflight_h
#define hookkit_inline_preflight_h

#import <HookKit/Compat.h>

#include <stddef.h>
#include <stdint.h>

// Overwrite windows, in bytes: Dobby's relocator takes 16 bytes, litehook's
// trampoline emits 5 instructions (4x MOVK + BR) = 20 bytes.
#define HK_INLINE_PREFLIGHT_DOBBY_WINDOW    16
#define HK_INLINE_PREFLIGHT_LITEHOOK_WINDOW 20

// Validates `function`/`replacement` for an inline overwrite of `window`
// bytes. Returns HK_OK when the prologue can be overwritten safely; otherwise
// HK_ERR_NOT_SUPPORTED with *outErrno (may be NULL) set to the reason
// (EINVAL: misaligned target or self-hook; EOPNOTSUPP: the function ends
// inside the window or a literal load / ADR(ADRP) sits in it).
hookkit_status_t hk_inline_preflight(void *function, void *replacement, size_t window, int *outErrno);

#endif
