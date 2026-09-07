"""Exercise the real fstatat/faccessat hook control flow with host doubles."""

import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ShadowCore.dylib/hooks/Universal/libc.x"
PATH_REWRITE = ROOT / "src/ShadowCore.dylib/hooks/Universal/path_rewrite.c"


source = SOURCE.read_text()
start = source.index("static int (*original_fstatat)")
end = source.index("// readdir/readdir_r filtering", start)
hook = source[start:end].replace(
    "[_shadow isCPathRestricted:pathname]", "is_restricted(pathname)"
)

prefix = r'''
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

typedef bool BOOL;
static bool external = true;
static int rewrites;

#define isCallerExternal() external
#define SHADOW_TRIP(...) ((void)0)

int shdw_path_is_absolute(const char *path);

static bool is_restricted(const char *path) {
    return path && (!strcmp(path, "d0") || !strcmp(path, "/restricted"));
}

static bool shdw_libc_try_rewrite(const char *path) {
    rewrites++;
    ((char *)path)[0] = '\1';
    return true;
}

static bool shdw_at_path_denied(int dirfd, const char *path) {
    (void)dirfd;
    if(path && path[0] == '/' && is_restricted(path)) {
        errno = ENOENT;
        return true;
    }
    return false;
}

static bool shdw_is_restricted_root(const char *path) {
    return is_restricted(path);
}

static int real_fstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    (void)dirfd;
    (void)buf;
    (void)flags;
    if(path[0] == '\1') {
        errno = ENOENT;
        return -1;
    }
    return 71;
}

static int real_faccessat(int dirfd, const char *path, int mode, int flags) {
    (void)dirfd;
    (void)mode;
    (void)flags;
    if(path[0] == '\1') {
        errno = ENOENT;
        return -1;
    }
    return 72;
}
'''

suffix = r'''
int main(void) {
    struct stat st;
    original_fstatat = real_fstatat;
    original_faccessat = real_faccessat;

    char fstatat_relative[] = "d0";
    rewrites = 0;
    assert(replaced_fstatat(42, fstatat_relative, &st, 0) == 71);
    assert(!strcmp(fstatat_relative, "d0"));
    assert(rewrites == 0);

    char faccessat_relative[] = "d0";
    rewrites = 0;
    assert(replaced_faccessat(42, faccessat_relative, F_OK, 0) == 72);
    assert(!strcmp(faccessat_relative, "d0"));
    assert(rewrites == 0);

    char absolute[] = "/restricted";
    rewrites = 0;
    assert(replaced_fstatat(AT_FDCWD, absolute, &st, 0) == -1);
    assert((unsigned char)absolute[0] == 1);
    assert(rewrites == 1);

    puts("verify-at-path-rewrite: all assertions passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="shadow-at-rewrite-") as tmp:
    test = Path(tmp) / "test.c"
    executable = Path(tmp) / "test"
    test.write_text(prefix + hook + suffix)
    subprocess.run([
        os.environ.get("CC", "cc"), "-D_GNU_SOURCE", "-std=c11", "-Wall", "-Wextra",
        "-I", str(PATH_REWRITE.parent), str(test), str(PATH_REWRITE), "-o", str(executable),
    ], check=True)
    subprocess.run([str(executable)], check=True)
