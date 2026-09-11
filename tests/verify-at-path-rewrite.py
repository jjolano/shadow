"""Exercise the real fstatat/faccessat hook control flow with host doubles."""

import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ShadowCore.dylib/hooks/Universal/libc.x"
PATH_REWRITE = ROOT / "src/ShadowCore.dylib/hooks/Universal/path_rewrite.c"


source = SOURCE.read_text()
start = source.index("static int (*original_fstatat)(int dirfd")
end = source.index("// readdir/readdir_r filtering", start)
hook = source[start:end].replace(
    "[_shadow isCPathRestricted:pathname]", "is_restricted(pathname)"
)

prefix = r'''
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
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

static bool fast_allowed;
static bool shdw_is_fast_allowed_cpath(const char *path) {
    (void)path;
    return fast_allowed;
}

static bool shdw_path_is_external_hidden(const char *path) {
    (void)path;
    return false;
}

static bool shdw_path_is_external_hidden_lexical(const char *path) {
    (void)path;
    return false;
}
static int verify_gate_result;
static int shdw_verify_open_hidden(int dirfd, const char *path) {
    (void)dirfd; (void)path;
    if(verify_gate_result == -1) {
        errno = ENOENT;
    }
    return verify_gate_result;
}
typedef enum {
    SHDW_POST_ADMIT = 0,
    SHDW_POST_DENY_HIDDEN,
    SHDW_POST_DENY_CONTRADICTION,
} shdw_post_verdict_t;
static int post_verify_result;
static unsigned post_verify_calls;
static shdw_post_verdict_t shdw_at_post_verify(int dirfd, const char *path) {
    (void)dirfd; (void)path;
    post_verify_calls++;
    return (shdw_post_verdict_t)post_verify_result;
}

static bool shdw_path_under_system_bind_root(const char *path) {
    (void)path;
    return false;
}

static bool shdw_path_is_main_bundle_exempt(const char *path) {
    // Own-bundle sentinel for the exemption branches: no other test path
    // carries this prefix, so existing assertions are unaffected.
    return path && !strncmp(path, "/bundle", strlen("/bundle"));
}

// Substitution double (libc.x stat/fstatat pin-the-object verifier):
// controllable so the hook wiring pins all three outcomes (0 answers
// shaped, -1 denies shaped, -2 falls back to the shared re-verifier).
static bool need_verify;
static int sub_result = -2;
static unsigned sub_calls;
static bool shdw_path_needs_verify(const char *p) {
    (void)p;
    return need_verify;
}
static int shdw_stat_substitute(int dirfd, const char *p, struct stat *st, int flags) {
    (void)dirfd; (void)p; (void)flags;
    sub_calls++;
    if(sub_result == -1) {
        memset(st, 0, sizeof(*st));
        errno = ENOENT;
    } else if(sub_result == 0) {
        memset(st, 0xAB, sizeof(*st));
    }
    return sub_result;
}

typedef enum {
    SHADW_DIRFD_OK = 0,
    SHADW_DIRFD_ABSOLUTE,
    SHADW_DIRFD_ORIGINAL,
    SHADW_DIRFD_DENY,
} shdw_dirfd_status_t;

// Mirrors the real resolver contract (PathPolicy.m): empty path replays,
// absolute paths ignore the dirfd, AT_FDCWD and known dirfds resolve.
// dirfd 43 stands in for a bundle directory fd so the exemption-join
// branches execute end to end.
static shdw_dirfd_status_t shdw_resolve_dirfd_path(int dirfd, const char *path, char *out, size_t outlen) {
    (void)outlen;
    if(!path || !path[0]) {
        return SHADW_DIRFD_ORIGINAL;
    }
    if(path[0] == '/') {
        return SHADW_DIRFD_ABSOLUTE;
    }
    if(dirfd == AT_FDCWD) {
        strcpy(out, "/cwd");
        return SHADW_DIRFD_OK;
    }
    if(dirfd == 43) {
        strcpy(out, "/bundle");
        return SHADW_DIRFD_OK;
    }
    if(dirfd == 42) {
        strcpy(out, "/parent");
        return SHADW_DIRFD_OK;
    }
    return SHADW_DIRFD_ORIGINAL;
}

static dev_t shdw_rootfs_dev(void) {
    return 0;
}

// Post-use re-verification doubles (PathPolicy.h): controllable so the
// hook wiring pins both the pass-through and the deny shapes.
static bool post_hidden;
static unsigned post_calls;
static bool shdw_path_post_hidden(const char *path) {
    (void)path;
    post_calls++;
    return post_hidden;
}
static bool shdw_at_post_hidden(int dirfd, const char *path) {
    (void)dirfd;
    (void)path;
    post_calls++;
    return post_hidden;
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

    // A relative leaf joining onto the exempt bundle passes straight
    // through: no rewrite, no denial, input untouched.
    char fstatat_exempt[] = "leaf";
    rewrites = 0;
    assert(replaced_fstatat(43, fstatat_exempt, &st, 0) == 71);
    // Substitution: needs_verify gates it; 0 answers from the pinned
    // object (0xAB-shaped buffer), -1 denies shaped, -2 falls back to
    // the original (buffer untouched) plus the shared re-verifier
    // (tri-state: either deny shape refuses, admit passes through).
    need_verify = false;
    sub_calls = 0;
    post_verify_result = SHDW_POST_ADMIT;
    memset(&st, 1, sizeof(st));
    assert(replaced_stat("/allowed", &st) == 0 && sub_calls == 0);
    {
        struct stat untouched;
        memset(&untouched, 1, sizeof(untouched));
        assert(!memcmp(&st, &untouched, sizeof(st)));
    }
    need_verify = true;
    sub_result = 0;
    memset(&st, 0, sizeof(st));
    assert(replaced_stat("/allowed", &st) == 0 && sub_calls == 1);
    {
        struct stat pat;
        memset(&pat, 0xAB, sizeof(pat));
        assert(!memcmp(&st, &pat, sizeof(st)));
    }
    sub_result = -1;
    memset(&st, 1, sizeof(st));
    assert(replaced_stat("/allowed", &st) == -1 && errno == ENOENT && sub_calls == 2);
    {
        struct stat zero = {0};
        assert(!memcmp(&st, &zero, sizeof(st)));
    }
    sub_result = -2;
    post_verify_result = SHDW_POST_DENY_HIDDEN;
    assert(replaced_stat("/allowed", &st) == -1 && errno == ENOENT && sub_calls == 3);
    post_verify_result = SHDW_POST_DENY_CONTRADICTION;
    assert(replaced_stat("/allowed", &st) == -1 && errno == ENOENT && sub_calls == 4);
    post_verify_result = SHDW_POST_ADMIT;
    memset(&st, 1, sizeof(st));
    assert(replaced_stat("/allowed", &st) == 0 && sub_calls == 5);
    {
        struct stat untouched;
        memset(&untouched, 1, sizeof(untouched));
        assert(!memcmp(&st, &untouched, sizeof(st)));
    }
    need_verify = false;
    post_hidden = true;
    assert(replaced_access("/allowed", F_OK) == -1 && errno == ENOENT);
    post_hidden = false;
    char fstatat_post[] = "d0";
    sub_calls = 0;
    memset(&st, 1, sizeof(st));
    assert(replaced_fstatat(42, fstatat_post, &st, 0) == 71 && sub_calls == 0);
    need_verify = true;
    sub_result = 0;
    assert(replaced_fstatat(42, fstatat_post, &st, 0) == 0 && sub_calls == 1);
    sub_result = -1;
    assert(replaced_fstatat(42, fstatat_post, &st, 0) == -1 && errno == ENOENT && sub_calls == 2);
    sub_result = -2;
    post_verify_result = SHDW_POST_DENY_HIDDEN;
    assert(replaced_fstatat(42, fstatat_post, &st, 0) == -1 && errno == ENOENT && sub_calls == 3);
    post_verify_result = SHDW_POST_ADMIT;
    assert(replaced_fstatat(42, fstatat_post, &st, 0) == 71 && sub_calls == 4);
    need_verify = false;
    // Resolve-stable fast lane: the access gate pins benign links like
    // their targets and reports denials directly; gate-unavailable falls
    // back to the original plus the shared re-verifier. The stat lane
    // answers from the original plus the final link-appeared/vanish
    // check (metadata only); ruleset verdicts stay unconsulted here.
    fast_allowed = true;
    need_verify = true;
    verify_gate_result = 0;
    assert(replaced_access("/tmp/probe", F_OK) == 0);
    verify_gate_result = -1;
    assert(replaced_access("/tmp/probe", F_OK) == -1 && errno == ENOENT);
    verify_gate_result = -2;
    post_verify_result = SHDW_POST_ADMIT;
    assert(replaced_access("/tmp/probe", F_OK) == 0);
    post_verify_result = SHDW_POST_DENY_HIDDEN;
    assert(replaced_access("/tmp/probe", F_OK) == -1 && errno == ENOENT);
    post_verify_result = SHDW_POST_DENY_CONTRADICTION;
    assert(replaced_access("/tmp/probe", F_OK) == -1 && errno == ENOENT);
    post_verify_result = SHDW_POST_ADMIT;
    verify_gate_result = 0;
    // Fast stat lane: substitution answers, fallback re-verifies; ruleset
    // verdicts stay unconsulted here.
    sub_result = 0;
    memset(&st, 0, sizeof(st));
    assert(replaced_stat("/tmp/probe", &st) == 0);
    {
        struct stat pat;
        memset(&pat, 0xAB, sizeof(pat));
        assert(!memcmp(&st, &pat, sizeof(st)));
    }
    sub_result = -1;
    memset(&st, 1, sizeof(st));
    assert(replaced_stat("/tmp/probe", &st) == -1 && errno == ENOENT);
    {
        struct stat zero = {0};
        assert(!memcmp(&st, &zero, sizeof(st)));
    }
    sub_result = -2;
    post_verify_result = SHDW_POST_DENY_HIDDEN;
    memset(&st, 1, sizeof(st));
    assert(replaced_stat("/tmp/probe", &st) == -1 && errno == ENOENT);
    post_verify_result = SHDW_POST_DENY_CONTRADICTION;
    memset(&st, 1, sizeof(st));
    assert(replaced_stat("/tmp/probe", &st) == -1 && errno == ENOENT);
    post_verify_result = SHDW_POST_ADMIT;
    memset(&st, 1, sizeof(st));
    assert(replaced_stat("/tmp/probe", &st) == 0);
    {
        struct stat untouched;
        memset(&untouched, 1, sizeof(untouched));
        assert(!memcmp(&st, &untouched, sizeof(st)));
    }
    fast_allowed = false;
    post_hidden = false;
    need_verify = false;

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
