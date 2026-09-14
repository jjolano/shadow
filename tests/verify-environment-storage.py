"""Run the production TLS lifecycle with real threads and injected key failures."""
import os
from pathlib import Path
import re
import subprocess
import tempfile


def anchor_pattern(needle):
    """Regex for `needle`, tolerant of reformat spacing.

    These gates locate real source snippets by text and pin them. A
    clang-format pass must not be able to break that, so the pattern matches
    identifier/punctuation tokens separated by any whitespace, while the
    token sequence itself stays exact.
    """
    return r"\s*".join(
        re.escape(tok) for tok in re.findall(r"[A-Za-z0-9_]+|[^\sA-Za-z0-9_]", needle)
    )


def anchor(text, needle, start=0):
    """Index of `needle` in `text`, tolerant of reformat spacing."""
    match = re.search(anchor_pattern(needle), text[start:])
    if match is None:
        raise ValueError(f"anchor not found: {needle!r}")
    return start + match.start()


root = Path(__file__).resolve().parents[1]
source = (root / "src/ShadowCore.dylib/policy/EnvironmentPolicy.m").read_text()


def body(first, last):
    start = anchor(source, first)
    return source[start:anchor(source, last, start)]


storage = body("static _Thread_local char* shdw_env_path_storage", "// Shared PATH component filter")
storage += body("static void shdw_env_path_cache_invalidate(void)", "static int (*original_setenv)")
prefix = r'''
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
typedef bool BOOL;
#define NO false
static int failure, freed, registrations;
static void checked_free(void *p) { if(p) freed++; free(p); }
static int create_key(pthread_key_t *key, void (*destroy)(void *)) {
    if(failure == 1) return 11;
    return pthread_key_create(key, destroy);
}
static int set_key(pthread_key_t key, const void *value) {
    registrations++;
    if(failure == 2) return 12;
    return pthread_setspecific(key, value);
}
static void *get_key(pthread_key_t key) {
    assert(failure != 1);
    return pthread_getspecific(key);
}
#define free checked_free
#define pthread_key_create create_key
#define pthread_setspecific set_key
#define pthread_getspecific get_key
'''
suffix = r'''
static void *worker(void *unused) {
    (void)unused;
    if(failure) {
        assert(!shdw_env_tls_arm());
        if(failure == 1) return NULL;
        failure = 0;  // setspecific failure is retryable on the next call
    }
    assert(shdw_env_tls_arm());
    int before = registrations;
    assert(shdw_env_tls_arm());
    assert(registrations == before);
    shdw_env_path_storage = malloc(8);
    shdw_env_path_cache_input = malloc(8);
    shdw_env_path_cache_capacity = 8;
    shdw_env_path_cache_invalidate();
    assert(!shdw_env_path_cache_input && !shdw_env_path_cache_capacity);
    shdw_env_path_cache_input = malloc(8);
    shdw_env_snapshot_filtered = malloc(8);
    shdw_env_snapshot_path = malloc(8);
    shdw_env_procargs_path = malloc(8);
    return NULL;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    failure = atoi(argv[1]);
    int expected = failure == 1 ? 0 : 6;
    pthread_t thread;
    assert(pthread_create(&thread, NULL, worker, NULL) == 0);
    assert(pthread_join(thread, NULL) == 0);
    assert(freed == expected);
    assert(shdw_env_path_storage == NULL);  // worker storage is isolated
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="shadow-env-storage-") as tmp:
    test = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    test.write_text(prefix + storage + suffix)
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
                    "-Werror", "-pthread", str(test), "-o", str(binary)], check=True)
    for failure in range(3):
        subprocess.run([str(binary), str(failure)], check=True)

# Static ownership contract: capacity must be saved even when realloc stays put.
procargs = source[anchor(source, "void shdw_procargs2_filter("):]
assert not re.search(anchor_pattern("if(path_entry_storage != shdw_env_procargs_path)"), procargs)
assert re.search(anchor_pattern("shdw_env_procargs_path_cap = path_entry_capacity;"), procargs)
assert re.search(anchor_pattern("e[5] && shdw_env_tls_arm()"), procargs)
print("verify-environment-storage: thread cleanup, setup failures, and capacity contract passed")
