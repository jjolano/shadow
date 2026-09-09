"""Exercise the real fresh fd/DIR path-policy bodies with host doubles."""

import os
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "src/ShadowCore.dylib/policy/PathPolicy.m"
HEADER = ROOT / "src/ShadowCore.dylib/policy/PathPolicy.h"
LIBC = ROOT / "src/ShadowCore.dylib/hooks/Universal/libc.x"
SYSCALL = ROOT / "src/ShadowCore.dylib/hooks/Universal/syscall.x"
SVC = ROOT / "src/ShadowCore.dylib/hooks/Universal/svc_patch.x"


source = POLICY.read_text()
header = HEADER.read_text()
libc = LIBC.read_text()
syscall = SYSCALL.read_text()
svc = SVC.read_text()

for stale in ("shdw_fd_cache", "shdw_readdir_cache", "SHADW_FD_CACHE", "SHADW_READDIR_CACHE"):
    assert stale not in source and stale not in header and stale not in libc, stale

assert '{ "close",' not in libc
assert '{ "closedir",' not in libc
assert "CFRelease(nil) is a no-op" not in libc


def body(first, last):
    return source[source.index(first):source.index(last, source.index(first))]


resolver = body("shdw_dirfd_status_t shdw_resolve_dirfd_path", "// Applies the shared dirfd resolution")
at_path = body("BOOL shdw_at_path_denied", "// fd→path classification")
fd_path = body("BOOL shdw_fd_path_restricted", "// Returns a retained options dict")
readdir = body("NSDictionary* shdw_readdir_options", "// Classifies a readlink result")
libc_fstat = libc[libc.index("static int (*original_fstat)"):libc.index("static int (*original_fstatat)")]
libc_readdir_r = libc[libc.index("static int (*original_readdir_r)"):libc.index("static struct dirent* (*original_readdir)")]
libc_readdir = libc[libc.index("static struct dirent* (*original_readdir)"):libc.index("// --- Phase 3:")]

old_at = '''        NSString* path = [NSString stringWithUTF8String:pathname];
        BOOL restricted = [_shadow isPathRestricted:path options:@{
            kShadowRestrictionWorkingDir : [NSString stringWithUTF8String:parent]
        }];'''
assert old_at in at_path
at_path = at_path.replace(old_at, "        BOOL restricted = is_at_restricted(parent, pathname);")
at_path = at_path.replace("[_shadow isCPathRestricted:pathname]", "is_restricted(pathname)")

assert "fcntl(fd, F_GETPATH, pathname) != -1" in fd_path
fd_path = fd_path.replace("[_shadow isCPathRestricted:pathname]", "is_restricted(pathname)")

old_readdir = '''        NSDictionary* options = @{kShadowRestrictionWorkingDir : [NSString stringWithUTF8String:pathname]};
        errno = saved_errno;
        return (__bridge NSDictionary*)CFRetain((__bridge CFDictionaryRef)options);'''
assert old_readdir in readdir
readdir = readdir.replace("NSDictionary* shdw_readdir_options", "const char* shdw_readdir_options")
readdir = readdir.replace(old_readdir, '''        strlcpy(g_readdir_options, pathname, sizeof(g_readdir_options));
        errno = saved_errno;
        return g_readdir_options;''')
readdir = readdir.replace("strlcpy(g_readdir_options", "test_strlcpy(g_readdir_options")
readdir = readdir.replace("return nil;", "return NULL;")

for reader, boxed_name in (
    (libc_readdir_r, "@((*oresult)->d_name)"),
    (libc_readdir, "@(result->d_name)"),
):
    assert re.search(r"if\(options\)\s*\{\s*CFRelease\(", reader, re.S)
    reader = reader.replace("NSDictionary* options = shdw_readdir_options", "const char* options = shdw_readdir_options")
    reader = reader.replace("@autoreleasepool {", "{")
    reader = reader.replace(f"[_shadow isPathRestricted:{boxed_name} options:options]", "false")
    reader = reader.replace("CFRelease((__bridge CFDictionaryRef)options);", "CFRelease(options);")
    if boxed_name == "@((*oresult)->d_name)":
        libc_readdir_r = reader
    else:
        libc_readdir = reader

for category, argument in (
    ("SHADW_RAW_CAT_FDPATH", "srcfd"),
    ("SHADW_RAW_CAT_FDOFF", "fd"),
    ("SHADW_RAW_CAT_FDMODE", "fd"),
    ("SHADW_RAW_CAT_FDUIDGID", "fd"),
    ("SHADW_RAW_CAT_FDXATTR", "fd"),
    ("SHADW_RAW_CAT_FREADLINK", "fd"),
):
    assert re.search(rf"case {category}.*?shdw_fd_path_restricted\({argument}\)", syscall, re.S), category
assert "shdw_fd_path_restricted((int)a0)" in svc


prefix = r'''
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif
#ifndef F_GETPATH
#define F_GETPATH 50
#endif

typedef bool BOOL;
#define YES true
#define NO false

typedef enum {
    SHADW_DIRFD_OK = 0,
    SHADW_DIRFD_ABSOLUTE,
    SHADW_DIRFD_ORIGINAL,
    SHADW_DIRFD_DENY,
} shdw_dirfd_status_t;

typedef struct { int fd; } DIR;
struct dirent { char d_name[256]; };

static const char* paths[32];
static bool directories[32];
static unsigned getpath_calls;
static char g_readdir_options[PATH_MAX];
static bool external = true;
static unsigned releases;

static void CFRelease(const void* object) {
    assert(object);
    releases++;
}

static size_t test_strlcpy(char* dst, const char* src, size_t size) {
    size_t length = strlen(src);
    if(size) {
        size_t copy = length < size - 1 ? length : size - 1;
        memcpy(dst, src, copy);
        dst[copy] = '\0';
    }
    return length;
}

static int test_fcntl(int fd, int command, ...) {
    va_list args;
    va_start(args, command);
    char* out = va_arg(args, char*);
    va_end(args);
    assert(command == F_GETPATH);
    getpath_calls++;
    if(fd >= 0 && fd < (int)(sizeof(paths) / sizeof(paths[0])) && paths[fd]) {
        test_strlcpy(out, paths[fd], PATH_MAX);
        return 0;
    }
    errno = EIO;
    return -1;
}

static int test_fstat(int fd, struct stat* st) {
    if(fd >= 0 && fd < (int)(sizeof(directories) / sizeof(directories[0])) && directories[fd]) {
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFDIR;
        return 0;
    }
    errno = EBADF;
    return -1;
}

static char* test_getcwd(char* out, size_t size) {
    test_strlcpy(out, "/allowed/cwd", size);
    return out;
}

static int test_dirfd(DIR* dirp) {
    if(!dirp) {
        errno = EBADF;
        return -1;
    }
    return dirp->fd;
}

static bool is_restricted(const char* path) {
    return path && !strncmp(path, "/restricted", strlen("/restricted"));
}

static bool is_at_restricted(const char* parent, const char* path) {
    return is_restricted(parent) || is_restricted(path);
}

static bool shdw_path_is_external_hidden(const char* path) {
    (void)path;
    return false;
}

static bool shdw_dir_leaf_external_hidden(const char* parent, const char* name) {
    (void)parent;
    (void)name;
    return false;
}

static bool shdw_dir_entry_external_hidden(const char* options, const char* name) {
    (void)options;
    (void)name;
    return false;
}

#define fcntl test_fcntl
#define fstat test_fstat
#define getcwd test_getcwd
#define dirfd test_dirfd
#define isCallerExternal() external
'''

suffix = r'''
static int test_original_fstat(int fd, struct stat* st) {
    (void)fd;
    (void)st;
    return 71;
}

static int readdir_r_calls;
static int readdir_calls;
static struct dirent readdir_entry;

static int test_original_readdir_r(DIR* dirp, struct dirent* entry, struct dirent** result) {
    (void)dirp;
    readdir_r_calls++;
    test_strlcpy(entry->d_name, "allowed", sizeof(entry->d_name));
    *result = entry;
    return 0;
}

static struct dirent* test_original_readdir(DIR* dirp) {
    (void)dirp;
    readdir_calls++;
    test_strlcpy(readdir_entry.d_name, "allowed", sizeof(readdir_entry.d_name));
    return &readdir_entry;
}

static bool raw_fd_decision(int fd) {
    return shdw_fd_path_restricted(fd);
}

int main(void) {
    DIR stream = { .fd = 10 };
    struct stat st;
    struct dirent entry;
    struct dirent* out;
    BOOL denied = NO;
    const char* options;

    original_fstat = test_original_fstat;
    original_readdir_r = test_original_readdir_r;
    original_readdir = test_original_readdir;

    // dup2 can replace a number without close, including a standard stream.
    paths[7] = "/allowed/first";
    errno = EAGAIN;
    assert(!shdw_fd_path_restricted(7) && errno == EAGAIN);
    paths[7] = "/restricted/replaced";
    assert(shdw_fd_path_restricted(7) && errno == EAGAIN);
    paths[7] = "/allowed/replaced";
    assert(!shdw_fd_path_restricted(7) && errno == EAGAIN);
    paths[0] = "/restricted/reused-stdin";
    assert(shdw_fd_path_restricted(0));

    // Rename keeps the vnode/inode but F_GETPATH must be sampled again.
    paths[8] = "/allowed/open-file";
    errno = EAGAIN;
    assert(replaced_fstat(8, &st) == 71 && errno == EAGAIN);
    paths[8] = "/restricted/renamed-open-file";
    assert(replaced_fstat(8, &st) == -1 && errno == EBADF);

    // The actual libc hook and raw shared policy stay equal after each mutation.
    paths[9] = "/allowed/raw";
    errno = EBUSY;
    assert(replaced_fstat(9, &st) == 71 && !raw_fd_decision(9) && errno == EBUSY);
    paths[9] = "/restricted/raw";
    errno = EBUSY;
    assert(replaced_fstat(9, &st) == -1 && errno == EBADF);
    errno = EBUSY;
    assert(raw_fd_decision(9) && errno == EBUSY);

    // A parent-directory rename changes both readdir and relative *at policy.
    directories[10] = true;
    paths[10] = "/allowed/parent";
    errno = EBUSY;
    options = shdw_readdir_options(&stream, &denied);
    assert(options && !strcmp(options, "/allowed/parent") && !denied && errno == EBUSY);
    assert(!shdw_at_path_denied(10, "child") && errno == EBUSY);
    paths[10] = "/restricted/parent";
    options = shdw_readdir_options(&stream, &denied);
    assert(options && !strcmp(options, "/restricted/parent") && !denied && errno == EBUSY);
    assert(shdw_at_path_denied(10, "child") && errno == ENOENT);

    // A closed DIR* may be reused at the same address with a different fd.
    stream.fd = 11;
    directories[11] = true;
    paths[11] = "/allowed/reused-dir";
    errno = EBUSY;
    options = shdw_readdir_options(&stream, &denied);
    assert(options && !strcmp(options, "/allowed/reused-dir") && !denied && errno == EBUSY);
    assert(!shdw_at_path_denied(11, "child") && errno == EBUSY);

    // A nameable failure on a valid directory remains fail-closed; invalid
    // descriptors leave errno for the original readdir to report.
    stream.fd = 12;
    directories[12] = true;
    errno = EBUSY;
    assert(!shdw_readdir_options(&stream, &denied) && denied && errno == ENOENT);
    stream.fd = 13;
    errno = EBUSY;
    assert(!shdw_readdir_options(&stream, &denied) && !denied && errno == EBUSY);

    // Actual reader hooks must forward an invalid DIR* without CFRelease(NULL).
    out = NULL;
    assert(replaced_readdir_r(&stream, &entry, &out) == 0 && out == &entry && readdir_r_calls == 1 && releases == 0);
    assert(replaced_readdir(&stream) == &readdir_entry && readdir_calls == 1 && releases == 0);

    // A resolved parent returns retained options and releases them exactly once.
    stream.fd = 10;
    paths[10] = "/allowed/reader";
    out = NULL;
    assert(replaced_readdir_r(&stream, &entry, &out) == 0 && out == &entry && readdir_r_calls == 2 && releases == 1);
    assert(replaced_readdir(&stream) == &readdir_entry && readdir_calls == 2 && releases == 2);

    // A valid but unnameable directory remains denied without reader ownership.
    stream.fd = 12;
    out = &entry;
    assert(replaced_readdir_r(&stream, &entry, &out) == 0 && out == NULL && readdir_r_calls == 2 && releases == 2);
    assert(replaced_readdir(&stream) == NULL && readdir_calls == 2 && releases == 2);

    // Non-nameable fd classifiers are predicates and do not leak F_GETPATH's errno.
    errno = EBUSY;
    assert(!shdw_fd_path_restricted(14) && errno == EBUSY);
    assert(getpath_calls >= 17);
    puts("verify-fd-path-freshness: all assertions passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="shadow-fd-freshness-") as tmp:
    test = Path(tmp) / "test.c"
    executable = Path(tmp) / "test"
    test.write_text(prefix + resolver + at_path + fd_path + readdir + libc_fstat + libc_readdir_r + libc_readdir + suffix)
    subprocess.run([
        os.environ.get("CC", "cc"), "-D_GNU_SOURCE", "-std=c11", "-Wall", "-Wextra",
        str(test), "-o", str(executable),
    ], check=True)
    subprocess.run([str(executable)], check=True)
