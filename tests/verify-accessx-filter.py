"""Drive the production accessx_np/SYS_access_extended batch filter.

The production snapshot and filter bodies are extracted from
policy/PathPolicy.m; only the ObjC ruleset call is rewritten to a host double.
Buffers use the kernel's layout ([accessx_descriptor; 16 bytes][NUL-terminated
names], 16-byte aligned string starts), and result arrays carry the kernel's
answers so tests can verify input/output aliasing and per-entry behavior.
"""
import os
import re
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / "src/ShadowCore.dylib/policy/PathPolicy.m").read_text()


def anchor(text, needle, start=0):
    """Index of `needle` in `text`, tolerant of reformat spacing."""
    pattern = r"\s*".join(
        re.escape(tok) for tok in re.findall(r"[A-Za-z0-9_]+|[^\sA-Za-z0-9_]", needle)
    )
    match = re.search(pattern, text[start:])
    if match is None:
        raise ValueError(f"anchor not found: {needle!r}")
    return start + match.start()


start = anchor(source, "size_t shdw_accessx_filter(")
body = source[start:]
body = body[:body.rfind("}") + 1]
snapshot_start = anchor(source, "shdw_accessx_snapshot_status_t shdw_accessx_snapshot(")
snapshot_end = source.index("size_t shdw_accessx_filter(", snapshot_start)
snapshot_body = source[snapshot_start:snapshot_end].rstrip()
svc = (root / "src/ShadowCore.dylib/hooks/Universal/svc_patch.x").read_text()
status_error_start = anchor(svc, "static int shdw_svc_accessx_snapshot_error(")
status_error_end = svc.index("\n}\n", status_error_start) + 2
snapshot_error_body = svc[status_error_start:status_error_end]
assert "shdw_svc_accessx_snapshot_error(status, size)" in svc, \
    "inline svc must map snapshot status and size before invoking the kernel"

assert "shdw_path_is_external_hidden(name)" in body, (
    "accessx filter must use the shared external-hidden predicate")
assert "shdw_path_is_main_bundle_exempt(name)" in body, (
    "accessx filter must keep the main-bundle exemption")
assert "[_shadow isCPathRestricted:name]" in body, (
    "accessx filter must use the shared ruleset predicate")
body = body.replace("[_shadow isCPathRestricted:name]",
                    "test_is_cpath_restricted(name)")
assert "[_shadow" not in body and "@" not in body, "ObjC rewrite leaked"

PREFIX = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
typedef uintptr_t vm_address_t;
typedef uintptr_t vm_offset_t;
typedef size_t vm_size_t;
typedef uint32_t mach_msg_type_number_t;
typedef int vm_map_read_t;
typedef int vm_map_t;
typedef int kern_return_t;
#define KERN_SUCCESS 0
#define KERN_INVALID_ADDRESS 1
#define KERN_PROTECTION_FAILURE 2
static kern_return_t vm_read_result = KERN_SUCCESS;
static int vm_write_fails;
static vm_map_t mach_task_self(void) { return 1; }
static kern_return_t vm_read_overwrite(vm_map_read_t task, vm_address_t address,
                                       vm_size_t size, vm_address_t data,
                                       vm_size_t *outsize) {
    (void)task;
    if(vm_read_result != KERN_SUCCESS)
        return vm_read_result;
    if(!address || !data || !outsize)
        return KERN_INVALID_ADDRESS;
    memcpy((void *)(uintptr_t)data, (const void *)(uintptr_t)address, size);
    *outsize = size;
    return KERN_SUCCESS;
}
static kern_return_t vm_write(vm_map_t task, vm_address_t address,
                              vm_offset_t data, mach_msg_type_number_t size) {
    (void)task;
    if(vm_write_fails || !address || !data)
        return KERN_INVALID_ADDRESS;
    memcpy((void *)(uintptr_t)address, (const void *)(uintptr_t)data, size);
    return KERN_SUCCESS;
}
typedef enum {
    SHDW_ACCESSX_SNAPSHOT_READY,
    SHDW_ACCESSX_SNAPSHOT_MALFORMED,
    SHDW_ACCESSX_SNAPSHOT_SOURCE_FAULT,
    SHDW_ACCESSX_SNAPSHOT_UNAVAILABLE,
} shdw_accessx_snapshot_status_t;

typedef int BOOL;
#define YES 1
#define NO 0
#ifndef PATH_MAX
#define PATH_MAX 1024
#endif
static int ranges_disjoint(const void *a, size_t an, const void *b, size_t bn) {
    uintptr_t pa = (uintptr_t)a, pb = (uintptr_t)b;
    return pa + an <= pb || pb + bn <= pa;
}

#define DESC_SIZE 16
#define READ_FLAG 0x200

static BOOL shdw_path_is_main_bundle_exempt(const char *p) {
    return p && strcmp(p, "/app/exempt") == 0;
}
static BOOL shdw_path_is_external_hidden(const char *p) {
    return p && (strcmp(p, "/hidden/one") == 0 || strcmp(p, "/app/exempt") == 0);
}
static BOOL test_is_cpath_restricted(const char *p) {
    return p && (strcmp(p, "/ruleset/blocked") == 0 ||
                 strcmp(p, "/app/exempt") == 0);
}

static int failures;
#define CHECK(cond, what) do { if(!(cond)) { failures++; \
    printf("FAIL: %s\n", what); } } while(0)
#define CANARY 0x11223344

static size_t build(const char *const *paths, int n, unsigned char *buf,
                    size_t cap) {
    memset(buf, 0, cap);
    size_t off = (size_t)n * DESC_SIZE;
    for (int i = 0; i < n; i++) {
        size_t len = strlen(paths[i]) + 1;
        if (off + len > cap)
            return 0;
        uint32_t o = (uint32_t)off;
        int flags = READ_FLAG;
        memcpy(buf + i * DESC_SIZE, &o, sizeof(o));
        memcpy(buf + i * DESC_SIZE + 4, &flags, sizeof(flags));
        memcpy(buf + off, paths[i], len);
        off += len;
        if (i + 1 < n)
            off = (off + (DESC_SIZE - 1)) & ~(size_t)(DESC_SIZE - 1);
    }
    return off;
}
'''

SUFFIX = r'''
int main(void) {
    CHECK(shdw_svc_accessx_snapshot_error(SHDW_ACCESSX_SNAPSHOT_READY, 18) == 0,
          "ready snapshot continues");
    CHECK(shdw_svc_accessx_snapshot_error(
              SHDW_ACCESSX_SNAPSHOT_MALFORMED, 17) == EINVAL,
          "undersize malformed snapshot preserves kernel EINVAL");
    CHECK(shdw_svc_accessx_snapshot_error(
              SHDW_ACCESSX_SNAPSHOT_MALFORMED, 16 * 1024 + 1) == ENOMEM,
          "oversize malformed snapshot preserves kernel ENOMEM");
    CHECK(shdw_svc_accessx_snapshot_error(
              SHDW_ACCESSX_SNAPSHOT_SOURCE_FAULT, 18) == EFAULT,
          "unreadable entries preserve kernel EFAULT");
    CHECK(shdw_svc_accessx_snapshot_error(
              SHDW_ACCESSX_SNAPSHOT_UNAVAILABLE, 18) == ENOENT,
          "valid-size snapshot allocation failure fails closed");


    unsigned char buf[4096];
    int res[8];
    /* Private input/output stay disjoint even when caller results alias entries. */
    {
        union { int align; unsigned char bytes[4096]; } alias_buf;
        const char *paths[3] = {"/hidden/one", "/absent/control", "/usr/lib/dyld"};
        size_t size = build(paths, 3, alias_buf.bytes, sizeof(alias_buf.bytes));
        int private_results[128];
        private_results[0] = 0; private_results[1] = ENOENT; private_results[2] = 0;
        private_results[3] = CANARY;
        int *aliased_results = (int *)alias_buf.bytes;
        aliased_results[3] = CANARY;

        void *snapshot = NULL;
        shdw_accessx_snapshot_status_t status =
            shdw_accessx_snapshot(alias_buf.bytes, size, &snapshot);
        CHECK(status == SHDW_ACCESSX_SNAPSHOT_READY && snapshot,
              "input snapshot mapped");
        if(snapshot) {
            CHECK(ranges_disjoint(snapshot, size, alias_buf.bytes,
                                  sizeof(alias_buf.bytes)),
                  "snapshot does not overlap caller entries/results");
            CHECK(ranges_disjoint(snapshot, size, private_results,
                                  sizeof(private_results)),
                  "snapshot does not overlap private results");
            uint32_t hidden_offset;
            memcpy(&hidden_offset, snapshot, sizeof(hidden_offset));
            size_t count = shdw_accessx_filter(snapshot, size, private_results);
            CHECK(count == 3, "kernel descriptor count returned");
            CHECK(private_results[0] == ENOENT, "private hidden result rewritten");
            CHECK(private_results[1] == ENOENT, "private absent control preserved");
            CHECK(private_results[2] == 0, "private benign control preserved");
            CHECK(private_results[3] == CANARY, "private result tail untouched");
            CHECK(aliased_results[0] == (int)hidden_offset,
                  "filter did not read or write caller results");
            CHECK(shdw_accessx_write_results(aliased_results, private_results, count),
                  "filtered results copied back");
            CHECK(aliased_results[0] == ENOENT, "aliased hidden result written back");
            CHECK(aliased_results[1] == ENOENT, "aliased absent result written back");
            CHECK(aliased_results[2] == 0, "aliased benign result written back");
            CHECK(aliased_results[3] == CANARY, "copyout wrote only descriptor results");
            CHECK(strcmp((char *)snapshot + hidden_offset, "/hidden/one") == 0,
                  "snapshot keeps the original hidden spelling");

            int untouched[3] = {CANARY, CANARY, CANARY};
            vm_write_fails = 1;
            CHECK(!shdw_accessx_write_results(untouched, private_results, 3),
                  "failed caller copyout is reported");
            vm_write_fails = 0;
            CHECK(untouched[0] == CANARY, "failed copyout leaves output unchanged");
            munmap(snapshot, size);
        }
    }

    /* A genuine source fault is distinguishable from unavailable storage. */
    {
        const char *paths[1] = {"/hidden/one"};
        size_t size = build(paths, 1, buf, sizeof(buf));
        void *snapshot = NULL;
        vm_read_result = KERN_INVALID_ADDRESS;
        shdw_accessx_snapshot_status_t status =
            shdw_accessx_snapshot(buf, size, &snapshot);
        CHECK(status == SHDW_ACCESSX_SNAPSHOT_SOURCE_FAULT && !snapshot,
              "source fault is reported to the caller");
        vm_read_result = KERN_SUCCESS;
    }

    /* mixed H/A/B: only H is rewritten; A's real ENOENT and B's success stay */
    {
        const char *paths[3] = {"/hidden/one", "/absent/control", "/usr/lib/dyld"};
        size_t size = build(paths, 3, buf, sizeof(buf));
        CHECK(size > 0, "mixed buffer built");
        for (int i = 0; i < 8; i++) res[i] = CANARY;
        res[0] = 0; res[1] = ENOENT; res[2] = 0;
        shdw_accessx_filter(buf, size, res);
        CHECK(res[0] == ENOENT, "hidden entry rewritten");
        CHECK(res[1] == ENOENT, "absent control keeps kernel ENOENT");
        CHECK(res[2] == 0, "benign control keeps kernel success");
        CHECK(res[3] == CANARY, "slot past the kernel count untouched");
        res[0] = EACCES;
        shdw_accessx_filter(buf, size, res);
        CHECK(res[0] == ENOENT, "external-hidden entry overrides kernel error");
    }

    /* ruleset predicate is the second leg */
    {
        const char *paths[1] = {"/ruleset/blocked"};
        size_t size = build(paths, 1, buf, sizeof(buf));
        CHECK(size > 0, "ruleset buffer built");
        res[0] = 0;
        shdw_accessx_filter(buf, size, res);
        CHECK(res[0] == ENOENT, "ruleset-hidden entry rewritten");
        res[0] = EACCES;
        shdw_accessx_filter(buf, size, res);
        CHECK(res[0] == EACCES, "ruleset-only kernel error is preserved");
    }

    /* own-bundle exemption wins over both predicates */
    {
        const char *paths[1] = {"/app/exempt"};
        size_t size = build(paths, 1, buf, sizeof(buf));
        CHECK(size > 0, "exempt buffer built");
        res[0] = 0;
        shdw_accessx_filter(buf, size, res);
        CHECK(res[0] == 0, "main-bundle exemption preserved");
    }

    /* controls-only batch: nothing rewritten */
    {
        const char *paths[2] = {"/absent/control", "/usr/lib/dyld"};
        size_t size = build(paths, 2, buf, sizeof(buf));
        CHECK(size > 0, "control buffer built");
        res[0] = ENOENT; res[1] = 0;
        shdw_accessx_filter(buf, size, res);
        CHECK(res[0] == ENOENT && res[1] == 0, "controls-only untouched");
    }

    /* offset 0 chains the previous name's verdict */
    {
        memset(buf, 0, sizeof(buf));
        uint32_t o0 = 48, o2;
        int flags = READ_FLAG;
        memcpy(buf + 0, &o0, sizeof(o0));
        memcpy(buf + 4, &flags, sizeof(flags));
        /* slot 1: name offset 0 (chain slot 0) */
        size_t off = 48;
        memcpy(buf + off, "/hidden/one", strlen("/hidden/one") + 1);
        off += strlen("/hidden/one") + 1;
        off = (off + 15) & ~(size_t)15;
        o2 = (uint32_t)off;
        memcpy(buf + 2 * DESC_SIZE, &o2, sizeof(o2));
        memcpy(buf + 2 * DESC_SIZE + 4, &flags, sizeof(flags));
        memcpy(buf + off, "/usr/lib/dyld", strlen("/usr/lib/dyld") + 1);
        off += strlen("/usr/lib/dyld") + 1;
        res[0] = 0; res[1] = 0; res[2] = 0;
        shdw_accessx_filter(buf, off, res);
        CHECK(res[0] == ENOENT, "chain head rewritten");
        CHECK(res[1] == ENOENT, "chain slot inherits hidden verdict");
        CHECK(res[2] == 0, "benign slot after chain untouched");
    }

    /* exact-end name (the kernel's own NUL is the last byte) */
    {
        const char *paths[1] = {"/hidden/one"};
        size_t size = build(paths, 1, buf, sizeof(buf));
        CHECK(size > 0, "exact-end buffer built");
        CHECK(buf[size - 1] == 0, "builder puts the NUL at size-1");
        res[0] = 0;
        shdw_accessx_filter(buf, size, res);
        CHECK(res[0] == ENOENT, "exact-end name classified");
    }

    /* malformed shapes the kernel would reject: never touched */
    {
        memset(buf, 0, sizeof(buf));
        uint32_t bad = 0;
        memcpy(buf, &bad, sizeof(bad)); /* first-slot chain */
        res[0] = 0;
        shdw_accessx_filter(buf, 1024, res);
        CHECK(res[0] == 0, "first-slot chain ignored");

        bad = 1024; /* offset == size */
        memcpy(buf, &bad, sizeof(bad));
        res[0] = 0;
        shdw_accessx_filter(buf, 1024, res);
        CHECK(res[0] == 0, "out-of-range offset ignored");

        /* slot 0 points at 32, slot 1 points at 16 (j <= i) */
        uint32_t o = 32;
        memcpy(buf + 0, &o, sizeof(o));
        o = 16;
        memcpy(buf + DESC_SIZE, &o, sizeof(o));
        res[0] = res[1] = 0;
        shdw_accessx_filter(buf, 64, res);
        CHECK(res[0] == 0 && res[1] == 0, "backward descriptor ignored");

        res[0] = 0;
        shdw_accessx_filter(buf, 10, res);
        void *malformed_snapshot = (void *)1;
        CHECK(shdw_accessx_snapshot(buf, 10, &malformed_snapshot) ==
                  SHDW_ACCESSX_SNAPSHOT_MALFORMED && !malformed_snapshot,
              "malformed size does not allocate a snapshot");
        shdw_accessx_filter(buf, 16 * 1024 + 1, res);
        CHECK(res[0] == 0, "oversized buffer ignored");
    }

    /* unterminated spelling: the kernel's copy terminates at size-1 */
    {
        memset(buf, 0, sizeof(buf));
        uint32_t o = DESC_SIZE;
        memcpy(buf, &o, sizeof(o));
        memcpy(buf + DESC_SIZE, "abc", 3);
        buf[DESC_SIZE + 3] = 'x'; /* caller buffer has no NUL before size-1 */
        res[0] = 0;
        shdw_accessx_filter(buf, DESC_SIZE + 4, res);
        CHECK(res[0] == 0, "unterminated benign spelling untouched");
    }

    return failures != 0;
}
'''

with tempfile.TemporaryDirectory(prefix="shadow-accessx-") as tmp:
    test = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    test.write_text(PREFIX + snapshot_error_body + "\n" + snapshot_body +
                    "\n" + body + SUFFIX)
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11",
                    "-Wall", "-Wextra", "-Werror", str(test), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)

libc = (root / "src/ShadowCore.dylib/hooks/Universal/libc.x").read_text()
for row in ('{ "accessx_np",', '{ "__access_extended",'):
    line = next((l for l in libc.splitlines() if row in l), "")
    assert line and "SHDW_HOOK_FALLBACK_REBIND" in line, (
        f"libc descriptor missing/without rebind fallback: {row}")
syscall = (root / "src/ShadowCore.dylib/hooks/Universal/syscall.x").read_text()
raw = (root / "src/ShadowCore.dylib/hooks/Universal/RawSyscalls.def").read_text()
assert re.search(r"SHADW_RAWSYSCALL\(SYS_access_extended,\s*ACCESSX,\s*ACCESSEXT,\s*0,\s*0\)", raw), \
    "raw access_extended must use ACCESSX"
assert "shdw_accessx_snapshot(ax_entries, ax_size, &ax_snapshot)" in syscall, \
    "raw dispatch must snapshot before forwarding"
assert "original_syscall(number, input, ax_size," in syscall and \
       "ax_private_results, ax_uid)" in syscall, \
    "raw dispatch must use private input/output buffers"
assert re.search(r"shdw_accessx_filter\(\s*ax_snapshot,\s*ax_size,\s*ax_private_results\)",
                 syscall), "raw dispatch must filter private results"
assert re.search(r"shdw_accessx_write_results\(\s*ax_results,\s*ax_private_results,\s*count\)",
                 syscall), "raw dispatch must copy filtered results to the caller"
assert "if(ax_snapshot_status == SHDW_ACCESSX_SNAPSHOT_UNAVAILABLE)" in syscall, \
    "raw allocation failure must fail closed"
assert '"cmn w0, #1\\n"' in svc and '"cbz w0, 1f\\n"' in svc and \
       '"cbz w0, 4f\\n"' in svc, \
    "svc ACCESSX sentinel and helper results must use 32-bit comparisons"


assert "shdw_accessx_call(entries, size, results, uid, original_accessx_np)" in libc, \
    "accessx_np must use shared private-buffer handling"
assert "shdw_accessx_call(entries, size, results, uid, original_access_extended)" in libc, \
    "__access_extended must use shared private-buffer handling"
assert "original(input, size, private_results, uid)" in libc, \
    "libc wrappers must forward private input and output buffers"
assert "shdw_accessx_filter(snapshot, size, private_results)" in libc, \
    "libc wrappers must filter private results"
assert "shdw_accessx_write_results(results, private_results, count)" in libc, \
    "libc wrappers must copy filtered results back"
assert "if(status == SHDW_ACCESSX_SNAPSHOT_UNAVAILABLE)" in libc, \
    "libc allocation failure must fail closed"
assert "const void *input = status == SHDW_ACCESSX_SNAPSHOT_READY ? snapshot : entries;" in libc, \
    "malformed libc snapshots must be forwarded unchanged for native kernel errors"
assert "ax_snapshot_status == SHDW_ACCESSX_SNAPSHOT_READY" in syscall and \
       "? ax_snapshot : ax_entries" in syscall, \
    "malformed raw snapshots must be forwarded unchanged for native kernel errors"
assert "MAP_ANON | MAP_PRIVATE" in snapshot_body and \
       "vm_read_overwrite(" in snapshot_body, \
    "snapshot must use a disjoint mapping populated by a fault-safe read"
assert "vm_write(" in body, "result copyout must be fault-safe"
assert re.search(r'hookRebindSymbol:@"syscall"\s+withReplacement:replaced_syscall',
                 syscall), "syscall import must remain rebound"
alias_start = syscall.index("if(sym___syscall && sym___syscall == sym_syscall)")
distinct_start = syscall.index("} else if(sym___syscall)", alias_start)
alias_branch = syscall[alias_start:distinct_start]
distinct_branch = syscall[distinct_start:]
assert 'hookRebindSymbol:@"__syscall"' in alias_branch and \
       "withReplacement:replaced_syscall" in alias_branch and \
       "outOldPtr:(void **) &original_syscall" in alias_branch, \
    "__syscall alias branch must rebind its C import name to the syscall replacement"
assert 'hookRebindSymbol:@"__syscall"' in distinct_branch and \
       "withReplacement:replaced___syscall" in distinct_branch and \
       "outOldPtr:(void **) &original___syscall" in distinct_branch, \
    "distinct __syscall must retain its own replacement and continuation"
assert "accessx_np_target && accessx_np_target == target" in libc, \
    "installer must deduplicate accessx aliases"
assert "shdw_sym_policy_lookup_syscall(symbol)" in \
    (root / "src/ShadowCore.dylib/hooks/Universal/dyld.x").read_text(), \
    "dlsym must consult the syscall policy"
assert 'strcmp(name, "syscall") == 0' in syscall and \
       'strcmp(name, "__syscall") == 0' in syscall, \
    "syscall dlsym policy must cover both names"

print("verify-accessx-filter: disjoint snapshots, private output, filtering and copyout passed")
