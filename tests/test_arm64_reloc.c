// Host-side unit test for the ARM64 relocator. Needs no ARM hardware -- it only
// exercises decode/re-encode, which is where the crashes come from.
//
//   clang -o /tmp/t tests/test_arm64_reloc.c native/hk_arm64.c && /tmp/t

#include "../native/hk_arm64.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define PC 0x1000ULL

static uint32_t out[64];

static uint64_t quad_at(size_t index) {
    uint64_t value;
    memcpy(&value, &out[index], sizeof(value));
    return value;
}

static size_t reloc(uint32_t insn) {
    memset(out, 0, sizeof(out));
    return hk_arm64_relocate(&insn, PC, 1, out, sizeof(out));
}

// --- encodings under test -------------------------------------------------
// LDR X16, #8    0x58000050      BR X16     0xD61F0200
// LDR X17, #8    0x58000051      BLR X16    0xD63F0200
// B #12          0x14000003      B #20      0x14000005

static void test_verbatim(void) {
    assert(reloc(0xAA0103E0) == 4);         // MOV X0, X1
    assert(out[0] == 0xAA0103E0);

    assert(reloc(0xD503201F) == 4);         // NOP
    assert(out[0] == 0xD503201F);

    // RET is position-independent: copied, not rewritten
    assert(reloc(0xD65F03C0) == 4);
    assert(out[0] == 0xD65F03C0);
}

static void test_adr(void) {
    // ADR X0, #0x100  -> target 0x1100
    assert(reloc(0x10000800) == 16);
    assert(out[0] == 0x58000040);           // LDR X0, #8
    assert(out[1] == 0x14000003);           // B #12
    assert(quad_at(2) == 0x1100);
}

static void test_adrp(void) {
    // ADRP X8, #1 page -> (PC & ~0xFFF) + 0x1000 = 0x2000
    assert(reloc(0xB0000008) == 16);
    assert(out[0] == 0x58000048);           // LDR X8, #8
    assert(out[1] == 0x14000003);
    assert(quad_at(2) == 0x2000);

    // ADRP X0, #-1 page -> 0x0 (immlo is bits 30:29, so -1 is 0xF0FFFFE0)
    assert(reloc(0xF0FFFFE0) == 16);
    assert(quad_at(2) == 0x0);

    // ADRP X0, #-4 pages -> -0x4000 from the page base
    assert(reloc(0x90FFFFE0) == 16);
    assert(quad_at(2) == (uint64_t)-0x3000);
}

static void test_b(void) {
    // B #0x40 -> 0x1040
    assert(reloc(0x14000010) == 16);
    assert(out[0] == 0x58000050);           // LDR X16, #8
    assert(out[1] == 0xD61F0200);           // BR X16
    assert(quad_at(2) == 0x1040);

    // B #-0x40 -> 0xFC0 (sign extension)
    assert(reloc(0x17FFFFF0) == 16);
    assert(quad_at(2) == 0xFC0);
}

static void test_bl(void) {
    // BL #0x40 -> 0x1040, and execution must resume after the literal
    assert(reloc(0x94000010) == 20);
    assert(out[0] == 0x58000070);           // LDR X16, #12
    assert(out[1] == 0xD63F0200);           // BLR X16
    assert(out[2] == 0x14000003);           // B #12, over the literal
    assert(quad_at(3) == 0x1040);
}

static void test_cond_branch(void) {
    // B.EQ #0x20 -> 0x1020
    assert(reloc(0x54000100) == 24);
    assert(out[0] == 0x54000040);           // B.EQ #8, at the absolute jump
    assert(out[1] == 0x14000005);           // B #20, over it
    assert(out[2] == 0x58000050);
    assert(out[3] == 0xD61F0200);
    assert(quad_at(4) == 0x1020);

    // CBZ X0, #0x20
    assert(reloc(0xB4000100) == 24);
    assert(out[0] == 0xB4000040);
    assert(out[1] == 0x14000005);
    assert(quad_at(4) == 0x1020);

    // CBNZ W3, #0x20 -- condition, width and register must survive
    assert(reloc(0x35000103) == 24);
    assert(out[0] == 0x35000043);
    assert(quad_at(4) == 0x1020);

    // TBZ X0, #0, #0x20 (imm14)
    assert(reloc(0x36000100) == 24);
    assert(out[0] == 0x36000040);
    assert(out[1] == 0x14000005);
    assert(quad_at(4) == 0x1020);
}

static void test_load_literal(void) {
    // LDR X0, #0x40 -> loads from 0x1040
    assert(reloc(0x58000200) == 20);
    assert(out[0] == 0x58000051);           // LDR X17, #8
    assert(out[1] == 0x14000003);
    assert(quad_at(2) == 0x1040);
    assert(out[4] == 0xF9400220);           // LDR X0, [X17]

    // LDR W5, #0x40
    assert(reloc(0x18000205) == 20);
    assert(out[4] == 0xB9400225);           // LDR W5, [X17]

    // LDRSW X2, #0x40
    assert(reloc(0x98000202) == 20);
    assert(out[4] == 0xB9800222);           // LDRSW X2, [X17]

    // LDR D1, #0x40 (SIMD)
    assert(reloc(0x5C000201) == 20);
    assert(out[4] == 0xFD400221);           // LDR D1, [X17]

    // LDR Q0, #0x40 (SIMD, 128-bit)
    assert(reloc(0x9C000200) == 20);
    assert(out[4] == 0x3DC00220);           // LDR Q0, [X17]

    // PRFM literal -> dropped to a NOP
    assert(reloc(0xD8000200) == 4);
    assert(out[0] == 0xD503201F);
}

static void test_terminators(void) {
    assert(hk_arm64_is_terminator(0xD65F03C0));     // RET
    assert(hk_arm64_is_terminator(0xD61F0200));     // BR X16
    assert(hk_arm64_is_terminator(0x14000010));     // B
    assert(!hk_arm64_is_terminator(0x94000010));    // BL is not a terminator
    assert(!hk_arm64_is_terminator(0xD63F0200));    // BLR is not a terminator
    assert(!hk_arm64_is_terminator(0xD503201F));    // NOP
    assert(!hk_arm64_is_terminator(0x54000100));    // B.cond falls through
}

static void test_has_early_terminator(void) {
    // Empty / too-short windows are not "early terminator".
    assert(!hk_arm64_has_early_terminator(NULL, 0));
    assert(!hk_arm64_has_early_terminator((const void *)0x1000, 0));
    assert(!hk_arm64_has_early_terminator((const void *)0x1000, 3));

    // A single RET is an early terminator.
    uint32_t ret = 0xD65F03C0;
    assert(hk_arm64_has_early_terminator(&ret, 4));

    // RETAA / RETAB (authenticated returns)
    uint32_t retaa = 0xD65F0BFC;
    assert(hk_arm64_has_early_terminator(&retaa, 4));
    uint32_t retab = 0xD65F0FFC;
    assert(hk_arm64_has_early_terminator(&retab, 4));

    // BRAAZ X17 / BRABZ X17 (authenticated indirect branches)
    uint32_t braaz = 0xD71F0BF1;
    assert(hk_arm64_has_early_terminator(&braaz, 4));
    uint32_t brabz = 0xD71F0FF1;    // key-B variant (bit 10 set)
    assert(hk_arm64_has_early_terminator(&brabz, 4));

    // Unconditional B in a window.
    uint32_t b = 0x14000010;
    assert(hk_arm64_has_early_terminator(&b, 4));

    // A 12-byte window of NOPs has no terminator...
    uint32_t nops[3] = { 0xD503201F, 0xD503201F, 0xD503201F };
    assert(!hk_arm64_has_early_terminator(nops, 12));

    // ...but a window with a terminator in the middle does, even if the
    // window extends past it.
    uint32_t mid[4] = { 0xD503201F, 0xD65F03C0, 0xD503201F, 0xD503201F };
    assert(hk_arm64_has_early_terminator(mid, 16));

    // BLRAA (authenticated call) is NOT a terminator.
    uint32_t blraaz = 0xD73F0BF1;
    assert(!hk_arm64_has_early_terminator(&blraaz, 4));

    // BLR is not a terminator.
    uint32_t blr = 0xD63F0200;
    assert(!hk_arm64_has_early_terminator(&blr, 4));

    // B.cond falls through — not a terminator.
    uint32_t bcond = 0x54000100;
    assert(!hk_arm64_has_early_terminator(&bcond, 4));

    // Trailing partial instruction (3 bytes) does not read past the window.
    uint32_t three = 0xD65F03C0;
    assert(!hk_arm64_has_early_terminator(&three, 3));
}

static void test_has_literal_load(void) {
    // LDR X0, #0x40 (literal) is a literal load.
    uint32_t ldr = 0x58000200;
    assert(hk_arm64_has_aarch64_literal_load(&ldr, 4));

    // PRFM literal.
    uint32_t prfm = 0xD8000200;
    assert(hk_arm64_has_aarch64_literal_load(&prfm, 4));

    // ADR / ADRP.
    uint32_t adr = 0x10000800;
    assert(hk_arm64_has_aarch64_literal_load(&adr, 4));
    uint32_t adrp = 0xB0000008;
    assert(hk_arm64_has_aarch64_literal_load(&adrp, 4));

    // NOP / ADD / RET are not literal loads.
    uint32_t nop = 0xD503201F;
    assert(!hk_arm64_has_aarch64_literal_load(&nop, 4));
    uint32_t add = 0x91000108;
    assert(!hk_arm64_has_aarch64_literal_load(&add, 4));
    uint32_t ret = 0xD65F03C0;
    assert(!hk_arm64_has_aarch64_literal_load(&ret, 4));

    // Empty / too-short windows.
    assert(!hk_arm64_has_aarch64_literal_load(NULL, 0));
    assert(!hk_arm64_has_aarch64_literal_load((const void *)0x1000, 3));
}

static void test_branch_emit(void) {
    assert(hk_arm64_branch_size(0x1000, 0x1040) == 4);
    assert(hk_arm64_branch_size(0x1000, 0x1000 + (1 << 27)) == 16);
    assert(hk_arm64_branch_size(0x10000000, 0x0) == 16);

    memset(out, 0, sizeof(out));
    assert(hk_arm64_emit_branch(out, 0x1000, 0x1040) == 4);
    assert(out[0] == 0x14000010);

    memset(out, 0, sizeof(out));
    assert(hk_arm64_emit_branch(out, 0x1000, 0xFC0) == 4);
    assert(out[0] == 0x17FFFFF0);

    memset(out, 0, sizeof(out));
    assert(hk_arm64_emit_branch(out, 0x1000, 0xF0000000) == 16);
    assert(out[0] == 0x58000050);
    assert(out[1] == 0xD61F0200);
    assert(quad_at(2) == 0xF0000000);
}

static void test_multi_and_capacity(void) {
    // A realistic prologue: ADRP/ADD then a stack push.
    uint32_t prologue[4] = { 0xB0000008, 0x91000108, 0xA9BF7BFD, 0x910003FD };
    memset(out, 0, sizeof(out));

    size_t written = hk_arm64_relocate(prologue, PC, 4, out, sizeof(out));
    assert(written == 16 + 4 + 4 + 4);
    assert(quad_at(2) == 0x2000);           // ADRP rewritten
    assert(out[4] == 0x91000108);           // ADD copied verbatim
    assert(out[5] == 0xA9BF7BFD);
    assert(out[6] == 0x910003FD);

    // Capacity is respected rather than overrun.
    uint32_t small[1] = { 0x54000100 };     // needs 24 bytes
    assert(hk_arm64_relocate(small, PC, 1, out, 16) == 0);

    assert(hk_arm64_relocate(NULL, PC, 1, out, sizeof(out)) == 0);
    assert(hk_arm64_relocate(small, PC, 0, out, sizeof(out)) == 0);
}

int main(void) {
    test_verbatim();
    test_adr();
    test_adrp();
    test_b();
    test_bl();
    test_cond_branch();
    test_load_literal();
    test_terminators();
    test_has_early_terminator();
    test_has_literal_load();
    test_branch_emit();
    test_multi_and_capacity();

    printf("all arm64 relocator tests passed\n");
    return 0;
}
