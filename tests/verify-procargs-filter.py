"""Pin the KERN_PROCARGS2 payload model and the in-place redaction.

xnu's sysctl_procargsx copies out `[int argc][exec_path\\0][NUL padding][argc
argument strings][environment strings]` — a flat string area with no pointer
array. The filter used to model `[argc][char* argv[argc+1]][char* envp…][blob]`,
so it read string bytes as pointers: it either bailed at its own "envp
terminator missing" guard (leaving DYLD_INSERT_LIBRARIES readable through
`sysctl(KERN_PROCARGS2, getpid())` while getenv/environ/NSProcessInfo hid it —
the contradiction the filter exists to prevent) or rewrote pointer-sized chunks
of the string area.

This extracts the real body, drives it with a payload built in the kernel's
shape, and parses the result the way a stock consumer does. The old shape is
driven too: it must come back byte-identical, so a regression to the pointer
model fails here instead of on device.

The body is Objective-C (one `@autoreleasepool` and one `[_shadow …]` call);
both call sites are rewritten to C doubles, and the rewrite is asserted so a
drifted extraction fails loudly rather than testing nothing.
"""

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "src/ShadowCore.dylib/policy/EnvironmentPolicy.m"


def anchor_pattern(needle):
    """Regex for `needle`, tolerant of reformat spacing (see verify-image-span)."""
    return r"\s*".join(
        re.escape(tok) for tok in re.findall(r"[A-Za-z0-9_]+|[^\sA-Za-z0-9_]", needle)
    )


def body(source, signature):
    """Brace-matched body (signature included) of one function."""
    match = re.search(anchor_pattern(signature), source)
    if match is None:
        raise ValueError(f"anchor not found: {signature!r}")
    start = source.index("{", match.end())
    depth, end = 1, start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


policy_src = POLICY.read_text()
procargs_fn = body(policy_src, "void shdw_procargs2_filter(")

# Adapt the two Objective-C sites. Each must match exactly once: a reformatted
# or renamed site has to fail the extraction check, not silently shrink what is
# under test.
assert procargs_fn.count("@autoreleasepool") == 1, (
    "shdw_procargs2_filter: expected exactly one @autoreleasepool site")
assert procargs_fn.count("[_shadow isCPathRestricted:a]") == 1, (
    "shdw_procargs2_filter: expected exactly one isCPathRestricted call site")
procargs_c = procargs_fn.replace("@autoreleasepool {", "{").replace(
    "[_shadow isCPathRestricted:a]", "shdw_test_cpath_restricted(a)")
assert "@autoreleasepool" not in procargs_c and "[_shadow" not in procargs_c, (
    "shdw_procargs2_filter: Objective-C sites survived the C rewrite")

HARNESS = r"""
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int BOOL;
#define YES 1
#define NO 0

/* ---- doubles for the production helpers the extracted body calls ---- */
static char *shdw_env_procargs_path = NULL;
static size_t shdw_env_procargs_path_cap = 0;

static BOOL shdw_env_tls_arm(void) { return YES; }

BOOL shdw_env_entry_hidden(const char *var) {
    return strncmp(var, "DYLD_", 5) == 0 ||
           strncmp(var, "JAILBREAKD_", 11) == 0 ||
           strncmp(var, "BOOTSTRAP_PREFIX", 16) == 0;
}

/* Same contract as the real sanitizer: NULL when nothing needed removing,
   otherwise a rebuilt entry in the caller's storage. */
char *shdw_env_sanitized_path_entry(const char *var, char **storage,
                                    size_t *capacity) {
    if (!storage || !capacity || strncmp(var, "PATH=", 5) != 0 || var[5] == 0)
        return NULL;

    char joined[1024];
    size_t out = 0;
    int changed = 0;
    const char *p = var + 5;
    joined[out++] = 'P'; joined[out++] = 'A'; joined[out++] = 'T';
    joined[out++] = 'H'; joined[out++] = '=';
    while (*p) {
        const char *sep = strchr(p, ':');
        size_t len = sep ? (size_t)(sep - p) : strlen(p);
        if (strncmp(p, "/var/jb", 7) != 0) {
            if (out > 5) joined[out++] = ':';
            memcpy(joined + out, p, len);
            out += len;
        } else {
            changed = 1;
        }
        if (!sep) break;
        p = sep + 1;
    }
    joined[out] = '\0';
    if (!changed) return NULL;

    size_t need = out + 1;
    if (need > *capacity) {
        char *grown = (char *)realloc(*storage, need);
        if (!grown) return NULL;
        *storage = grown;
        *capacity = need;
    }
    strcpy(*storage, joined);
    return *storage;
}

static BOOL shdw_test_cpath_restricted(const char *path) {
    return strncmp(path, "/var/jb", 7) == 0;
}

/* ---- extracted production logic ---- */
__PROCARGS_FN__

static int failures = 0;
#define CHECK(cond, ...) do { if (!(cond)) { failures++; \
    printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* A stock consumer: argc, exec path, alignment NULs, argc argv strings, then
   environment strings to the end of the buffer. */
typedef struct {
    int argc;
    const char *exec_path;
    const char *argv[8];
    const char *env[16];
    int env_count;
} parsed_t;

static size_t append_string(char *buf, size_t off, const char *s) {
    size_t n = strlen(s) + 1;
    memcpy(buf + off, s, n);
    return off + n;
}

static size_t build_payload(char *payload, size_t cap, int argc,
                            const char *exec_path, const char *const *argv,
                            int padding, const char *const *env, int env_count) {
    char strings[4096];
    size_t so = 0;

    so = append_string(strings, so, exec_path);

    for (int i = 0; i < padding; i++) strings[so++] = '\0';

    for (int i = 0; i < argc; i++) so = append_string(strings, so, argv[i]);
    for (int i = 0; i < env_count; i++) so = append_string(strings, so, env[i]);

    size_t len = sizeof(int) + so;
    if (len > cap) { printf("payload overflow\n"); exit(2); }

    memcpy(payload, &argc, sizeof(int));
    memcpy(payload + sizeof(int), strings, so);
    return len;
}

static parsed_t parse_payload(const char *payload, size_t len) {
    parsed_t out;
    memset(&out, 0, sizeof(out));

    memcpy(&out.argc, payload, sizeof(int));

    const char *p = payload + sizeof(int);
    const char *end = payload + len;

    out.exec_path = p;
    p += strlen(p) + 1;
    while (p < end && *p == '\0') p++;

    for (int i = 0; i < out.argc && p < end; i++) {
        out.argv[i] = p;
        p += strlen(p) + 1;
    }

    while (p < end) {
        out.env[out.env_count++] = p;
        p += strlen(p) + 1;
    }

    return out;
}

static int has_substr(const char *buf, size_t len, const char *needle) {
    size_t n = strlen(needle);
    if (n == 0 || n > len) return 0;
    for (size_t i = 0; i + n <= len; i++)
        if (memcmp(buf + i, needle, n) == 0) return 1;
    return 0;
}

int main(void) {
    static char payload[8192];
    size_t len;
    parsed_t parsed;

    const char *exec_path =
        "/private/var/containers/Bundle/Application/1A2B/App.app/App";
    const char *argv[] = { exec_path, "-insert",
                           "/var/jb/usr/lib/libhook.dylib" };
    const char *env[] = { "HOME=/var/mobile",
                          "PATH=/var/jb/usr/bin:/usr/bin:/bin",
                          "DYLD_INSERT_LIBRARIES=/var/jb/usr/lib/libsubstrate.dylib",
                          "BOOTSTRAP_PREFIX=/var/jb",
                          "TERM=xterm-256color" };

    len = build_payload(payload, sizeof(payload), 3, exec_path, argv, 3, env, 5);
    size_t original_len = len;

    shdw_procargs2_filter(payload, &len);

    CHECK(len < original_len, "payload must shrink, got %zu of %zu", len, original_len);
    CHECK(!has_substr(payload, len, "DYLD_INSERT_LIBRARIES"),
          "a DYLD_ entry stayed readable in the payload");
    CHECK(!has_substr(payload, len, "BOOTSTRAP_PREFIX"),
          "BOOTSTRAP_PREFIX stayed readable in the payload");
    CHECK(!has_substr(payload, len, "/var/jb"),
          "a jailbreak path stayed readable in the payload");

    parsed = parse_payload(payload, len);
    CHECK(parsed.argc == 1, "argv must lose the injection flag and its value, argc=%d",
          parsed.argc);
    CHECK(parsed.argc > 0 && strcmp(parsed.argv[0], exec_path) == 0,
          "argv[0] must survive, got %s",
          parsed.argc > 0 ? parsed.argv[0] : "(none)");
    CHECK(strcmp(parsed.exec_path, exec_path) == 0,
          "the exec path must be untouched, got %s", parsed.exec_path);

    CHECK(parsed.env_count == 3, "env must keep exactly the three benign entries, got %d",
          parsed.env_count);
    if (parsed.env_count == 3) {
        CHECK(strcmp(parsed.env[0], "HOME=/var/mobile") == 0,
              "env order must be preserved, got %s", parsed.env[0]);
        CHECK(strcmp(parsed.env[1], "PATH=/usr/bin:/bin") == 0,
              "PATH must keep its jailbreak-free components in order, got %s",
              parsed.env[1]);
        CHECK(strcmp(parsed.env[2], "TERM=xterm-256color") == 0,
              "the trailing entry must survive, got %s", parsed.env[2]);
    }

    /* The reported length must be the compacted payload: a consumer reads to it. */
    size_t expected = sizeof(int) + strlen(exec_path) + 1 + 3 +
                      strlen(exec_path) + 1 + strlen("HOME=/var/mobile") + 1 +
                      strlen("PATH=/usr/bin:/bin") + 1 +
                      strlen("TERM=xterm-256color") + 1;
    CHECK(len == expected, "oldlenp must be the compacted length (%zu), got %zu",
          expected, len);

    /* Nothing to drop: byte-identical, including the length. */
    const char *clean_argv[] = { exec_path };
    const char *clean_env[] = { "HOME=/var/mobile", "TERM=xterm-256color" };
    len = build_payload(payload, sizeof(payload), 1, exec_path, clean_argv, 2,
                        clean_env, 2);
    size_t before = len;
    static char snapshot[8192];
    memcpy(snapshot, payload, len);
    shdw_procargs2_filter(payload, &len);
    CHECK(len == before && memcmp(snapshot, payload, len) == 0,
          "a payload with nothing to drop must pass through byte-identical");

    /* The pointer-array shape this filter used to assume is not a
       KERN_PROCARGS2 payload at all: the kernel's exec path is always absolute
       and non-empty, this one's is the first byte of the 0/nonzero slot data
       (empty after the NUL). The whole payload must therefore be refused
       untouched — the old model rewrote pointer-sized chunks of it, and the
       droppable entry below is what makes "untouched" prove the refusal rather
       than a coincidence. */
    memset(payload, 0, sizeof(payload));
    int bogus_argc = 2;
    memcpy(payload, &bogus_argc, sizeof(int));
    uintptr_t slots[4] = { 0x1000, 0x2000, 0x3000, 0 };
    memcpy(payload + sizeof(int), slots, sizeof(slots));
    strcpy(payload + sizeof(int) + sizeof(slots),
           "DYLD_INSERT_LIBRARIES=x");
    len = sizeof(int) + sizeof(slots) + strlen("DYLD_INSERT_LIBRARIES=x") + 1;
    before = len;
    memcpy(snapshot, payload, len);
    shdw_procargs2_filter(payload, &len);
    CHECK(len == before && memcmp(snapshot, payload, len) == 0,
          "a payload without a plausible exec path must come back byte-identical");

    /* Unterminated tail: preserved, never read past the reported length. */
    len = build_payload(payload, sizeof(payload), 1, exec_path, clean_argv, 2,
                        clean_env, 2);
    char *tail_start = payload + len - strlen("TERM=xterm-256color") - 1;
    size_t tail_len = (size_t)(payload + len - tail_start);
    len -= 1; /* drop the final NUL: the tail string is now unterminated */
    before = len;
    memcpy(snapshot, payload, len);
    shdw_procargs2_filter(payload, &len);
    CHECK(len >= before - tail_len && len <= before,
          "an unterminated tail must not lengthen or truncate the payload "
          "(%zu -> %zu)", before, len);

    /* argc that the payload cannot back: refused, not guessed. */
    len = build_payload(payload, sizeof(payload), 1, exec_path, clean_argv, 2,
                        clean_env, 2);
    bogus_argc = 5000;
    memcpy(payload, &bogus_argc, sizeof(int));
    before = len;
    memcpy(snapshot, payload, len);
    shdw_procargs2_filter(payload, &len);
    CHECK(len == before && memcmp(snapshot, payload, len) == 0,
          "an argc the payload cannot hold must pass through untouched");

    free(shdw_env_procargs_path);

    if (failures) { printf("%d assertion(s) failed\n", failures); return 1; }
    printf("procargs filter: all assertions passed\n");
    return 0;
}
"""


def build_source():
    return HARNESS.replace("__PROCARGS_FN__", procargs_c)


def run():
    with tempfile.TemporaryDirectory() as tmp:
        c = Path(tmp) / "procargs.c"
        exe = Path(tmp) / "procargs"
        c.write_text(build_source())
        compiled = subprocess.run(
            [os.environ.get("CC", "cc"), "-std=c99", "-Wall", "-Wextra",
             "-Werror", "-o", str(exe), str(c)],
            capture_output=True, text=True)
        if compiled.returncode != 0:
            sys.stderr.write(compiled.stderr)
            return 1
        result = subprocess.run([str(exe)], capture_output=True, text=True)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode


if __name__ == "__main__":
    sys.exit(run())
