#ifndef hk_arm64_h
#define hk_arm64_h

// ARM64 (AArch64) instruction relocation for inline hooking.
//
// Deliberately not a disassembler: only the PC-relative forms need rewriting
// when instructions move, and in A64 that set is closed --
// ADR/ADRP, B/BL, B.cond, CBZ/CBNZ, TBZ/TBNZ and the load-literal group.
// Everything else in A64 is position-independent and is copied verbatim.
//
// This file is free of Mach/Darwin dependencies so the encoder/decoder can be
// unit-tested on the build host (see tests/test_arm64_reloc.c).

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Internal to the framework: HookKit's only exported symbol is _HKSubstitutor
// (see HookKit.tbd), and these must not join the dynamic export table.
#ifndef HK_INTERNAL
#define HK_INTERNAL __attribute__((visibility("hidden")))
#endif

// Worst-case bytes emitted per relocated instruction (the conditional-branch
// rewrite: cond + skip + 16-byte absolute jump).
#define HK_A64_MAX_RELOC_BYTES 24

// Longest branch sequence hk_arm64_emit_branch can produce.
#define HK_A64_MAX_BRANCH_BYTES 16

// True if `insn` ends the instruction stream (RET, unconditional B, BR).
// Used to detect a target function too short to patch safely.
HK_INTERNAL bool hk_arm64_is_terminator(uint32_t insn);

// True if any complete instruction in the window [win, win+len) is an early
// exit or unconditional control transfer that a prologue patch must not
// clobber: RET/RETAA/RETAB, BR/BRAA/BRAB/BRAAZ/BRABZ, unconditional B.
// Trailing partial instructions are ignored; never reads past `len`.
// Used to refuse patching a function that ends inside the overwrite window.
HK_INTERNAL bool hk_arm64_has_early_terminator(const void *win, size_t len);

// True if any complete instruction in the window is a PC-relative literal
// load (LDR literal / PRFM literal) or ADR/ADRP — forms whose relocation is
// fragile or fatal in Dobby-style relocators. Conservative: a false positive
// costs a declined backend, a false negative costs a crash.
HK_INTERNAL bool hk_arm64_has_aarch64_literal_load(const void *win, size_t len);

// Bytes a branch from `from` to `to` will occupy: 4 when a plain B reaches
// (+/-128MB), otherwise 16.
HK_INTERNAL size_t hk_arm64_branch_size(uint64_t from, uint64_t to);

// Emit a branch to `dest` into `buf`, which will live at `buf_addr`.
// Returns bytes written (4 or 16).
HK_INTERNAL size_t hk_arm64_emit_branch(uint32_t *buf, uint64_t buf_addr, uint64_t dest);

// Copy `count` instructions from `src` (originally at `src_addr`) into `dst`,
// rewriting PC-relative operands so they keep referring to their original
// targets. Every rewrite resolves to an absolute address, so where `dst` ends up
// does not matter.
//
// Returns bytes written to `dst`, or 0 if the sequence cannot be relocated or
// would exceed `dst_capacity`.
HK_INTERNAL size_t hk_arm64_relocate(const uint32_t *src, uint64_t src_addr, size_t count,
                                     uint32_t *dst, size_t dst_capacity);

#endif
