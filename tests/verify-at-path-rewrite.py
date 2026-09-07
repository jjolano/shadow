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
static int queries;
static bool rewrite_enabled = true;
#define NO false
#define YES true

#define isCallerExternal() external
#define SHADOW_TRIP(...) ((void)0)

int shdw_path_is_absolute(const char *path);

static bool is_restricted(const char *path) {
    queries++;
    return path && (!strcmp(path, "d0") || !strcmp(path, "/restricted"));
}

static bool shdw_libc_try_rewrite(const char *path) {
    if(!rewrite_enabled) return false;
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
    return path && !strcmp(path, "/restricted");
}

static bool shdw_is_fast_allowed_cpath(const char *path) {
    (void)path;
    return false;
}

static int real_access(const char *path, int mode) {
    (void)mode;
    if(path[0] == '\1') { errno = ENOENT; return -1; }
    return 0;
}

static int real_stat(const char *path, struct stat *buf) {
    (void)buf;
    return real_access(path, 0);
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
    original_access = real_access;
    original_stat = real_stat;

    rewrite_enabled = false;
    for(int ext = 0; ext <= 1; ext++) {
        external = ext;
        queries = 0;
        errno = EBUSY;
        assert(replaced_access("/allowed", F_OK) == 0);
        assert(errno == EBUSY && queries == 1);
        queries = 0;
        assert(replaced_access("/restricted", F_OK) == -1);
        assert(errno == ENOENT && queries == 1);
        queries = 0;
        memset(&st, 1, sizeof(st));
        assert(replaced_stat("/restricted", &st) == (ext ? -1 : 0));
        assert(queries == ext);
        if(ext) {
            struct stat zero = {0};
            assert(errno == ENOENT && !memcmp(&st, &zero, sizeof(st)));
        }
    }
    external = true;
    rewrite_enabled = true;
    char access_path[] = "/restricted";
    queries = 0;
    assert(replaced_access(access_path, F_OK) == -1 && queries == 1);
    char stat_path[] = "/restricted";
    queries = 0;
    assert(replaced_stat(stat_path, &st) == -1 && queries == 1);

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

for first, last in [("static int (*original_access)", "static ssize_t (*original_readlink)"),
                    ("static int (*original_stat)", "static int (*original_lstat)")]:
    hook += source[source.index(first):source.index(last)].replace(
        "[_shadow isCPathRestricted:pathname]", "is_restricted(pathname)"
    )

with tempfile.TemporaryDirectory(prefix="shadow-at-rewrite-") as tmp:
    test = Path(tmp) / "test.c"
    executable = Path(tmp) / "test"
    test.write_text(prefix + hook + suffix)
    subprocess.run([
        os.environ.get("CC", "cc"), "-D_GNU_SOURCE", "-std=c11", "-Wall", "-Wextra",
        "-I", str(PATH_REWRITE.parent), str(test), str(PATH_REWRITE), "-o", str(executable),
    ], check=True)
    subprocess.run([str(executable)], check=True)
