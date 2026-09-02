// Host-runnable check for the path-munging logic in
// src/ShadowCore.dylib/hooks/Universal/path_rewrite.c (pure C, no mach or
// Foundation, so it compiles and runs on the build host).
//
// Build and run:
//   cc -std=c99 -Wall -Wextra -o /tmp/opencode/rewrite-test tests/verify-path-rewrite.c src/ShadowCore.dylib/hooks/Universal/path_rewrite.c
//   /tmp/opencode/rewrite-test

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

int main(void) {
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
