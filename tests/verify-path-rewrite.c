// Host-runnable check for the path-munging logic in
// src/ShadowCore.dylib/hooks/Universal/path_rewrite.c (pure C, no mach or
// Foundation, so it compiles and runs on the build host).
//
// Build and run:
//   cc -std=c99 -Wall -Wextra -o /tmp/shadow-rewrite-test tests/verify-path-rewrite.c src/ShadowCore.dylib/hooks/Universal/path_rewrite.c
//   /tmp/shadow-rewrite-test

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/ShadowCore.dylib/hooks/Universal/path_rewrite.h"

static void expect_munge(const char *orig, const char *expected) {
    char buf[512];

    strcpy(buf, orig);
    assert(shdw_path_munge_path(buf) == 1);
    assert(strcmp(buf, expected) == 0);
    assert(strlen(buf) == strlen(expected));
}

// Regression for the const-mutation defect: the natural-ENOENT rewrite must
// produce a munged COPY and leave the caller's buffer byte-identical.
static void expect_copy_leaves_input(const char *orig, const char *expected) {
    char input[512];
    char scratch[512];

    strcpy(input, orig);
    const char *out = shdw_path_rewrite_copy(input, scratch, sizeof scratch);

    assert(out != NULL);
    assert(strcmp(out, expected) == 0);
    assert(strcmp(input, orig) == 0);   // caller's bytes untouched
    assert(out == scratch);
}

int main(void) {
    // Only absolute *at operands may use the in-place natural-ENOENT rewrite;
    // relative names must retain their dirfd-derived meaning.
    assert(shdw_path_is_absolute("/var/jb"));
    assert(shdw_path_is_absolute("/"));
    assert(!shdw_path_is_absolute("d0"));
    assert(!shdw_path_is_absolute(""));
    assert(!shdw_path_is_absolute(NULL));

    // Absolute path: middle of the final component flips to 0x01.
    expect_munge("/var/jb/usr/bin/ssh", "/var/jb/usr/bin/s\x01h");
    // Two-char final component.
    expect_munge("/var/jb/usr/bin/sh", "/var/jb/usr/bin/s\x01");
    // Single-char final component.
    expect_munge("/var/jb/x", "/var/jb/\x01");
    // Relative path.
    expect_munge("var/jb/ssh", "var/jb/s\x01h");
    // No '/' at all.
    expect_munge("ssh", "s\x01h");

    expect_copy_leaves_input("/var/jb/usr/bin/ssh",
                             "/var/jb/usr/bin/s\x01h");
    expect_copy_leaves_input("/var/mobile/tmp/eff_raceswap_a_9",
                             "/var/mobile/tmp/eff_race\x01wap_a_9");

    // Already-marked spelling: the copy helper must REFUSE (NULL) rather than return
    // an unmodified spelling, and the caller's buffer stays untouched.
    {
      char input[512];
      char scratch[512];
      strcpy(input, "/var/mobile/tmp/eff_race\x01wap_a_9");
      assert(shdw_path_rewrite_copy(input, scratch, sizeof scratch) == NULL);
      assert(strcmp(input, "/var/mobile/tmp/eff_race\x01wap_a_9") == 0);
      // Test contract: the copy helper refuses already-marked input; the in-place
      // primitive still rewrites.
      assert(shdw_path_munge_path(input) == 1);
    }

    // Nothing safe to munge: empty string, root, trailing slash.
    char buf[16];

    strcpy(buf, "");
    assert(shdw_path_munge_path(buf) == 0);
    strcpy(buf, "/");
    assert(shdw_path_munge_path(buf) == 0);
    strcpy(buf, "/var/jb/");
    assert(shdw_path_munge_path(buf) == 0);

    // Offset consistency: munge_offset agrees with munge_path and the byte
    // at the offset is the one that flips.
    const char *p = "/var/jb/usr/bin/ssh";
    size_t off = shdw_path_munge_offset(p);

    assert(off != (size_t)-1);
    char b2[64];

    strcpy(b2, p);
    assert(shdw_path_munge_offset(b2) == off);
    assert((unsigned char)b2[off] != 0x01);
    assert(shdw_path_munge_path(b2) == 1);
    assert((unsigned char)b2[off] == 0x01);

    printf("verify-path-rewrite: all assertions passed\n");
    return 0;
}
