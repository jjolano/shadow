"""Exercise the real lexical path standardizer with host doubles.

Extracts shdw_standardize_lexical from policy/PathPolicy.m (pure C over
<string.h> only) and pins its contract: canonical paths return identical
(no copy), degeneracies collapse to the kernel-resolved spelling, overlong
input falls back to the raw string, and non-absolute input passes through.
"""
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "src/ShadowCore.dylib/policy/PathPolicy.m"


source = POLICY.read_text()
start = source.index("const char* shdw_standardize_lexical(const char* path) {")
end = source.index("BOOL shdw_path_is_external_hidden", start)
routine = source[start:end]
# Immutable-prefix gate for alias resolution (pure C like the
# standardizer): system hot paths skip the resolving open, anything
# else resolves. A missing prefix only costs an open (fail closed);
# a wrongly listed one would leak, so the boundary cases are pinned.
gate_start = source.index("static BOOL shdw_path_under_immutable_prefix(const char* path) {")
gate_end = source.index("static _Thread_local char shdw_kernel_scratch", gate_start)
gate = source[gate_start:gate_end]

prefix = r'''
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef bool BOOL;
#define YES true
#define NO false

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static _Thread_local char shdw_lex_scratch[PATH_MAX];
'''

suffix = r'''
int main(void) {
    // Canonical absolute paths compare identical (fast path, no copy).
    const char* canon = "/usr/lib/systemhook.dylib";
    assert(shdw_standardize_lexical(canon) == canon);
    const char* root = "/";
    assert(shdw_standardize_lexical(root) == root);
    assert(!strcmp(shdw_standardize_lexical(root), "/"));
    // Dotfile names need no work and compare identical.
    const char* dotfile = "/usr/lib/.hidden";
    assert(shdw_standardize_lexical(dotfile) == dotfile);
    // Duplicate slashes collapse anywhere, including leading runs.
    assert(!strcmp(shdw_standardize_lexical("//usr/lib/systemhook.dylib"),
                   "/usr/lib/systemhook.dylib"));
    assert(!strcmp(shdw_standardize_lexical("/usr//lib//systemhook.dylib"),
                   "/usr/lib/systemhook.dylib"));

    // Dot segments drop out, including a trailing "/.".
    assert(!strcmp(shdw_standardize_lexical("/./usr/lib/systemhook.dylib"),
                   "/usr/lib/systemhook.dylib"));
    assert(!strcmp(shdw_standardize_lexical("/usr/lib/./systemhook.dylib"),
                   "/usr/lib/systemhook.dylib"));
    assert(!strcmp(shdw_standardize_lexical("/usr/lib/systemhook.dylib/."),
                   "/usr/lib/systemhook.dylib"));

    // Dot-dot pops lexically and clamps at root.
    assert(!strcmp(shdw_standardize_lexical("/usr/../usr/lib/systemhook.dylib"),
                   "/usr/lib/systemhook.dylib"));
    assert(!strcmp(shdw_standardize_lexical("/usr/lib/sub/../systemhook.dylib"),
                   "/usr/lib/systemhook.dylib"));
    assert(!strcmp(shdw_standardize_lexical("/../usr/lib/systemhook.dylib"),
                   "/usr/lib/systemhook.dylib"));
    assert(!strcmp(shdw_standardize_lexical("/a/../../usr/lib/x"), "/usr/lib/x"));

    // A single trailing slash is preserved: a directory spelling never
    // compares equal to a file.
    assert(!strcmp(shdw_standardize_lexical("/usr/lib/"), "/usr/lib/"));
    assert(!strcmp(shdw_standardize_lexical("/usr/lib//"), "/usr/lib/"));
    assert(!strcmp(shdw_standardize_lexical("/usr/./lib/"), "/usr/lib/"));

    // Degeneracies compose: stacked slashes feed dot pops.
    assert(!strcmp(shdw_standardize_lexical("//usr//lib//../lib//systemhook.dylib"),
                   "/usr/lib/systemhook.dylib"));

    // Non-absolute input passes through untouched.
    assert(!strcmp(shdw_standardize_lexical("usr/lib/x"), "usr/lib/x"));
    assert(!strcmp(shdw_standardize_lexical(""), ""));

    // Absurdly long input falls back to the raw string (fail open).
    static char huge[PATH_MAX + 64];
    memset(huge, 'a', sizeof(huge) - 1);
    huge[0] = '/';
    huge[sizeof(huge) - 1] = '\0';
    assert(shdw_standardize_lexical(huge) == huge);

    // The scratch result is only valid until the next call: a second
    // degenerate input may reuse it, so compare immediately.
    const char* first = shdw_standardize_lexical("//a//b");
    assert(!strcmp(first, "/a/b"));

    // Immutable gate: system prefixes skip resolution, everything else
    // (including boundary lookalikes) resolves.
    assert(shdw_path_under_immutable_prefix("/usr/lib/systemhook.dylib"));
    assert(shdw_path_under_immutable_prefix("/usr/lib/"));
    assert(shdw_path_under_immutable_prefix("/System/Library/x"));
    assert(shdw_path_under_immutable_prefix("/bin/sh"));
    assert(shdw_path_under_immutable_prefix("/Library/x"));
    assert(shdw_path_under_immutable_prefix("/private/preboot/x"));
    assert(shdw_path_under_immutable_prefix("/var/jb/x"));
    assert(shdw_path_under_immutable_prefix("/dev/null"));
    assert(!shdw_path_under_immutable_prefix("/var/mobile/x"));
    assert(!shdw_path_under_immutable_prefix("/private/var/mobile/x"));
    assert(!shdw_path_under_immutable_prefix("/tmp/x"));
    assert(!shdw_path_under_immutable_prefix("/private/tmp/x"));
    assert(!shdw_path_under_immutable_prefix("/var/tmp/x"));
    assert(!shdw_path_under_immutable_prefix("/usr2/x"));
    assert(!shdw_path_under_immutable_prefix("/usr"));
    assert(!shdw_path_under_immutable_prefix("relative/x"));
    assert(!shdw_path_under_immutable_prefix(""));

    puts("verify-path-standardize: all assertions passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="shadow-standardize-") as tmp:
    test = Path(tmp) / "test.c"
    executable = Path(tmp) / "test"
    test.write_text(prefix + routine + gate + suffix)
    subprocess.run([
        os.environ.get("CC", "cc"), "-D_GNU_SOURCE", "-std=c11", "-Wall", "-Wextra",
        str(test), "-o", str(executable),
    ], check=True)
    subprocess.run([str(executable)], check=True)
