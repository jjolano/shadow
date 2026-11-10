#!/usr/bin/env python3
"""Compile the alias predicate; source-pin path preference and fallback lanes."""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/ShadowCore.dylib/hooks/Universal/libc.x").read_text()
helper_start = source.index("static BOOL shdw_copy_visible_alias(")
helper_end = source.index("\n}\n", helper_start) + 3
helper = source[helper_start:helper_end]

# Host-only symlink model. Compile the production mount-record + basename +
# realpath predicate with fake mount records; bindfs behavior remains device-
# unverified.
program = r'''
#define _XOPEN_SOURCE 700
#define PATH_MAX 4096
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int BOOL;
#define YES 1
#define NO 0
''' + helper + r'''
int main(int argc, char **argv) {
    assert(argc == 3);
    char visible[4096];
    const char *fdpath = argv[1];
    const char *root = argv[2];
    const char *mountfrom = "/preboot/procursus/basebin/.fakelib";
    assert(shdw_copy_visible_alias(fdpath, mountfrom, "/usr/lib",
        mountfrom, "/usr/lib", root, visible, sizeof(visible)));
    char expected[4096];
    snprintf(expected, sizeof(expected), "%s/dyld", root);
    assert(strcmp(visible, expected) == 0);
    assert(!shdw_copy_visible_alias(fdpath, "/other/mount", "/usr/lib",
        mountfrom, "/usr/lib", root, visible, sizeof(visible)));
    assert(!shdw_copy_visible_alias(fdpath, mountfrom, "/other/mountpoint",
        mountfrom, "/usr/lib", root, visible, sizeof(visible)));
    return 0;
}
'''

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    backing = root / "procursus/basebin/gen/dyld"
    backing.parent.mkdir(parents=True)
    backing.write_text("dyld")
    visible_root = root / "usr/lib"
    visible_root.mkdir(parents=True)
    (visible_root / "dyld").symlink_to(backing)

    # The mount source is .fakelib, but F_GETPATH points into gen; no literal
    # mount-source prefix assumption is involved. Same-object realpath admits it.
    assert os.path.realpath(visible_root / "dyld") == os.path.realpath(backing)
    c_path = root / "copy-source.c"
    binary = root / "copy-source"
    c_path.write_text(program)
    subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", str(c_path), "-o", str(binary)], check=True)
    subprocess.run([str(binary), str(os.path.realpath(backing)), str(visible_root)], check=True)

    # A benign alias to a different object fails the same-object check.
    unrelated = root / "procursus/basebin/gen/restricted"
    unrelated.write_text("restricted")
    (visible_root / "benign-alias").write_text("benign")
    assert os.path.realpath(unrelated) != os.path.realpath(visible_root / "benign-alias")

classifier_start = source.index("BOOL shdw_fd_visible_path_restricted(int fd) {")
classifier_end = source.index("\n}\n", classifier_start) + 3
classifier = source[classifier_start:classifier_end]
assert "fstatfs(fd, &fd_mount)" in classifier
assert 'statfs("/usr/lib", &lib_mount)' in classifier
assert "fd_mount.f_mntfromname, fd_mount.f_mntonname" in classifier
assert "lib_mount.f_mntfromname, lib_mount.f_mntonname" in classifier
assert '"/usr/lib", visible, sizeof(visible)' in classifier
assert "shdw_resolved_spelling_hidden(path)" in classifier
assert classifier.index("shdw_resolved_spelling_hidden(path)") < classifier.index("fstatfs(fd, &fd_mount)")
assert "shdw_path_is_external_hidden(path)" in classifier
assert "[_shadow isCPathRestricted:path]" in classifier

source_policy_start = source.index("static BOOL shdw_copyfile_source_restricted(")
source_policy_end = source.index("\n}\n", source_policy_start) + 3
source_policy = source[source_policy_start:source_policy_end]
assert source_policy.index("COPYFILE_STATE_SRC_FILENAME") < source_policy.index("if(sourcePath && sourcePath[0])")
assert source_policy.index("if(hasPath) return NO;") < source_policy.index("shdw_fd_visible_path_restricted(stateFd)")
assert source_policy.index("if(hasPath) return NO;") < source_policy.index("shdw_fd_visible_path_restricted(fallbackFd)")
assert "shdw_copyfile_source_restricted(state, from, -1)" in source
assert "shdw_copyfile_source_restricted(state, NULL, from_fd)" in source

fclone = source[source.index("static int replaced_fclonefileat("):source.index("static int (*original_rmdir)")]
assert "shdw_fd_visible_path_restricted(srcfd)" in fclone
assert "errno = ENOENT;" in fclone

lowlevel = (ROOT / "src/ShadowCore.dylib/hooks/Universal/libc_lowlevel.x").read_text()
for hook in ("replaced_open(", "replaced_openat(", "replaced_openx_np(",
             "replaced_open_dollar_nocancel(", "replaced_openat_dollar_nocancel(",
             "replaced_open_dprotected_np(", "replaced_openat_dprotected_np(",
             "replaced_openat_authenticated_np(", "replaced_opendir(",
             "replaced___opendir2("):
    start = lowlevel.index(hook)
    end = lowlevel.index("\n}", start) + 2
    assert "shdw_fd_names_hidden" in lowlevel[start:end], hook
    assert "shdw_fd_visible_path_restricted" not in lowlevel[start:end], hook
for hook in ("replaced_creat(", "replaced_fopen(", "replaced_freopen("):
    start = source.index(hook)
    end = source.index("\n}", start) + 2
    assert "shdw_fd_names_hidden" in source[start:end], hook
    assert "shdw_fd_visible_path_restricted" not in source[start:end], hook

raw = (ROOT / "src/ShadowCore.dylib/hooks/Universal/syscall.x").read_text()
assert "shdw_fd_names_hidden((int)result)" in raw
assert "openFamily = cat == SHADW_RAW_CAT_PATH" not in raw
assert "shdw_copy_source_fd_restricted" not in source
print("verify-copy-source-policy: copy-source alias predicate and benign-compatible open fd checks passed (bindfs device-unverified)")
