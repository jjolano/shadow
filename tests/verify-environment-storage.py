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
# The dictionary view must be driven by the shared name predicate: a hand-kept
# list drifts (it had already lost BOOTSTRAP_PREFIX, which getenv hid while
# NSProcessInfo.environment still returned it).
dict_fn = body("NSDictionary *shdw_env_sanitized_dictionary(", "// PATH: drop jailbreak components")
assert "shdw_env_name_hidden(" in dict_fn, (
    "shdw_env_sanitized_dictionary must use the shared name predicate")
assert 'hasPrefix:@"DYLD_"' not in dict_fn, (
    "the dictionary view must not keep a private env-key list")

procargs = source[anchor(source, "void shdw_procargs2_filter("):]
assert not re.search(anchor_pattern("if(path_entry_storage != shdw_env_procargs_path)"), procargs)
assert re.search(anchor_pattern("shdw_env_procargs_path_cap = path_entry_capacity;"), procargs)
assert re.search(anchor_pattern("e[5] && shdw_env_tls_arm()"), procargs)

# Behavioral check for the shared name/entry predicate. Dopamine sets
# DOPAMINE_INITIALIZED and LAUNCHD_UUID in launchd; children inherit them.
# Pin both the new names and the boundary rules so a future prefix edit does
# not silently hide stock spellings.
env_start = anchor(source, "static BOOL shdw_env_hidden")
env_end = anchor(source, "BOOL shdw_env_name_hidden", env_start)
env_hidden = source[env_start:env_end]
env_hidden = env_hidden[:env_hidden.rfind("}") + 1]
assert "DOPAMINE_" in env_hidden and "LAUNCHD_UUID" in env_hidden, (
    "shdw_env_hidden must cover the Dopamine launch variables")

env_prefix = r'''
#include <stdio.h>
#include <string.h>
typedef int BOOL;
#define YES 1
#define NO 0
'''
env_suffix = r'''
static int failures;
#define CHECK(cond, what) do { if(!(cond)) { failures++; \
    printf("FAIL: %s\n", what); } } while(0)
#define NAME(s) shdw_env_hidden((s), '\0')
#define ENTRY(s) shdw_env_hidden((s), '=')
int main(void) {
    CHECK(NAME("DYLD_INSERT_LIBRARIES"), "DYLD_ name");
    CHECK(NAME("JAILBREAKD_FOO"), "JAILBREAKD_ name");
    CHECK(NAME("DOPAMINE_INITIALIZED"), "DOPAMINE_ name");
    CHECK(NAME("DOPAMINE_IS_HIDDEN"), "DOPAMINE_ hidden name");
    CHECK(NAME("JBUPDATE_PREV_VERSION"), "JBUPDATE_ name");
    CHECK(NAME("LAUNCHD_UUID"), "LAUNCHD_UUID name");
    CHECK(NAME("STAGED_JAILBREAK_UPDATE"), "STAGED_JAILBREAK_UPDATE name");
    CHECK(NAME("DISABLE_TWEAKS"), "DISABLE_TWEAKS name");
    CHECK(NAME("JBROOT") && NAME("SHADOW_JBROOT"), "jbroot hint names");
    CHECK(NAME("_MSSafeMode") && NAME("_SafeMode") &&
          NAME("_SubstituteSafeMode") && NAME("BOOTSTRAP_PREFIX"),
          "safe-mode names");

    CHECK(!NAME("DYLD"), "DYLD without underscore");
    CHECK(!NAME("JAILBREAKD"), "JAILBREAKD without underscore");
    CHECK(!NAME("DOPAMINE"), "DOPAMINE without underscore");
    CHECK(!NAME("JBUPDATE"), "JBUPDATE without underscore");
    CHECK(!NAME("LAUNCHD_UUIDX"), "LAUNCHD_UUID longer spelling");
    CHECK(!NAME("STAGED_JAILBREAK_UPDATE_X"), "STAGED... longer spelling");
    CHECK(!NAME("DISABLE_TWEAKS2"), "DISABLE_TWEAKS longer spelling");
    CHECK(!NAME("JBROOTX") && !NAME("SHADOW_JBROOTX"), "jbroot longer spelling");
    CHECK(!NAME("_MSSafeModeX") && !NAME("_SafeModeX") &&
          !NAME("_SubstituteSafeModeX") && !NAME("BOOTSTRAP_PREFIXX"),
          "safe-mode longer spellings");
    CHECK(!NAME("HOME") && !NAME("PATH"), "stock names");

    CHECK(ENTRY("DYLD_INSERT_LIBRARIES=/usr/lib/systemhook.dylib"), "DYLD entry");
    CHECK(ENTRY("JAILBREAKD_FOO=1"), "JAILBREAKD entry");
    CHECK(ENTRY("DOPAMINE_INITIALIZED=1"), "DOPAMINE entry");
    CHECK(ENTRY("JBUPDATE_PREV_VERSION=1"), "JBUPDATE entry");
    CHECK(ENTRY("LAUNCHD_UUID=ABC"), "LAUNCHD_UUID entry");
    CHECK(ENTRY("STAGED_JAILBREAK_UPDATE=/tmp/x"), "STAGED entry");
    CHECK(ENTRY("DISABLE_TWEAKS=1"), "DISABLE_TWEAKS entry");
    CHECK(ENTRY("JBROOT=/var/jb") && ENTRY("SHADOW_JBROOT=/var/jb"),
          "jbroot hint entries");
    CHECK(ENTRY("_MSSafeMode=1") && ENTRY("_SafeMode=1") &&
          ENTRY("_SubstituteSafeMode=1") && ENTRY("BOOTSTRAP_PREFIX=/var/jb"),
          "safe-mode entries");
    CHECK(!ENTRY("LAUNCHD_UUIDX=ABC"), "LAUNCHD_UUID longer entry");
    CHECK(!ENTRY("DISABLE_TWEAKS2=1"), "DISABLE_TWEAKS longer entry");
    CHECK(!ENTRY("HOME=/var/mobile"), "stock entry");
    return failures != 0;
}
'''
with tempfile.TemporaryDirectory(prefix="shadow-env-hidden-") as tmp:
    test = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    test.write_text(env_prefix + env_hidden + env_suffix)
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
                    "-Werror", str(test), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

# All four app-visible surfaces must route through the one predicate; a
# private list on either side is how BOOTSTRAP_PREFIX previously drifted.
libc_envvar = (root / "src/ShadowCore.dylib/hooks/Universal/libc_envvar.x").read_text()
assert "shdw_env_name_hidden(name)" in libc_envvar, (
    "getenv must use the shared name predicate")
snapshot_fn = body("char ***shdw_env_filtered_snapshot(", "// KERN_PROCARGS2")
assert "shdw_env_entry_hidden(raw[i])" in snapshot_fn, (
    "_NSGetEnviron must use the shared entry predicate")
env_mirror_fn = body("static void shdw_env_rebuild_locked(void)",
                     "// Public rebuild entry")
assert "shdw_env_entry_hidden(real[i])" in env_mirror_fn, (
    "raw environ must use the shared entry predicate")
assert "shdw_env_entry_hidden(e)" in procargs, (
    "KERN_PROCARGS2 must use the shared entry predicate")

print("verify-environment-storage: thread cleanup, setup failures, capacity and env-name contract passed")
