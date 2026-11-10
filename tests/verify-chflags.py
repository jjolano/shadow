"""Exercise the real chflags hook bodies with policy doubles."""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ShadowCore.dylib/hooks/Universal/libc.x"
source = SOURCE.read_text()


def function(name):
    start = source.index(f"static int replaced_{name}(")
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[start : end + 1].replace("[_shadow isCPathRestricted:pathname]", "restricted_path(pathname)")
    raise AssertionError(f"unterminated replaced_{name}")


prefix = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
typedef bool BOOL;
#define PATH_MAX 4096
typedef uint32_t __uint32_t;
#define F_GETPATH 1
#define YES true
#define NO false
static bool external = true, bundle, hidden, restricted;
static const char *fd_path = "/hidden";
static int original_calls, hidden_calls, restricted_calls, bundle_calls;
static int isCallerExternal(void) { return external; }
static bool shdw_path_is_main_bundle_exempt(const char *p) {
    bundle_calls++; return bundle && p && !strcmp(p, "/bundle/file");
}
static bool shdw_path_is_external_hidden(const char *p) {
    hidden_calls++; return hidden && p && !strcmp(p, "/hidden");
}
static bool restricted_path(const char *p) {
    restricted_calls++; return restricted && p && !strcmp(p, "/restricted");
}
static int test_fcntl(int fd, int command, char *path) {
    (void)fd; (void)command;
    strcpy(path, fd_path);
    return 0;
}
#define fcntl test_fcntl
typedef void *filesec_t;
static int original_chmodx_np(const char *p, filesec_t fsec) {
    (void)p; (void)fsec; original_calls++; return 20;
}
static int original_chflags(const char *p, uint32_t flags) {
    (void)p; (void)flags; original_calls++; return 17;
}
static int original_lchflags(const char *p, uint32_t flags) {
    (void)p; (void)flags; original_calls++; return 18;
}
static int original_fchflags(int fd, uint32_t flags) {
    (void)fd; (void)flags; original_calls++; return 19;
}
'''

suffix = r'''
int main(void) {
    errno = 0; hidden = true;
    assert(replaced_chflags("/hidden", 0) == -1 && errno == ENOENT);
    assert(original_calls == 0);
    errno = 0;
    assert(replaced_lchflags("/hidden", 0) == -1 && errno == ENOENT);
    assert(original_calls == 0);

    hidden = false; restricted = true; errno = 0;
    assert(replaced_chflags("/restricted", 0) == -1 && errno == ENOENT);
    assert(replaced_lchflags("/restricted", 0) == -1 && errno == ENOENT);

    bundle = true; hidden = true; restricted = true;
    int before = original_calls;
    assert(replaced_chflags("/bundle/file", 0) == 17);
    assert(replaced_lchflags("/bundle/file", 0) == 18);
    assert(original_calls == before + 2);

    external = false; before = original_calls;
    assert(replaced_chflags("/hidden", 0) == 17);
    assert(replaced_lchflags("/hidden", 0) == 18);
    assert(original_calls == before + 2);

    external = true; bundle = false; hidden = true; restricted = true; errno = 0;
    assert(replaced_chmodx_np("/hidden", NULL) == -1 && errno == ENOENT);
    assert(replaced_chmodx_np("/restricted", NULL) == -1 && errno == ENOENT);
    bundle = true; before = original_calls;
    assert(replaced_chmodx_np("/bundle/file", NULL) == 20);
    assert(original_calls == before + 1);
    external = false; bundle = false; before = original_calls;
    assert(replaced_chmodx_np("/hidden", NULL) == 20);
    assert(original_calls == before + 1);

    external = true; bundle = false; hidden = true; errno = 0;
    assert(replaced_fchflags(3, 0) == -1 && errno == EBADF);
    hidden = false; restricted = true; fd_path = "/restricted"; errno = 0;
    assert(replaced_fchflags(3, 0) == -1 && errno == EBADF);
    bundle = true; hidden = true; restricted = true; fd_path = "/bundle/file"; before = original_calls;
    assert(replaced_fchflags(3, 0) == 19);
    assert(original_calls == before + 1);
    external = false; before = original_calls;
    assert(replaced_fchflags(3, 0) == 19);
    assert(original_calls == before + 1);
    puts("verify-chflags: all assertions passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="shadow-chflags-") as tmp:
    test = Path(tmp) / "test.c"
    executable = Path(tmp) / "test"
    hooks = "\n".join(function(name) for name in ("chflags", "lchflags", "fchflags", "chmodx_np"))
    test.write_text(prefix + hooks + suffix)
    subprocess.run([
        os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
        str(test), "-o", str(executable),
    ], check=True)
    subprocess.run([str(executable)], check=True)
