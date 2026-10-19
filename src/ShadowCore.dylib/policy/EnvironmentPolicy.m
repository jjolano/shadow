// Environment sanitization policy. The rules here are shared verbatim by
// the getenv hook (libc.x), the _NSGetEnviron hook (syscall.x),
// -[NSProcessInfo environment/arguments] (NSProcessInfo.x) and the
// KERN_PROCARGS2 rebuild (libc.x sysctl + syscall.x raw dispatch +
// sysctlbyname) so every environment channel reports the same filtered
// view. Thread-local buffers are per-function by design: the getenv, the
// _NSGetEnviron snapshot and the PROCARGS2 rebuild each keep their OWN
// storage (a shared buffer would let one surface overwrite a pointer the
// other still hands out — getenv-style lifetime semantics).

#import "EnvironmentPolicy.h"

#import "../HookRuntime.h"
#import <Shadow/JBPath.h>

#ifndef SHADOW_TEST_HARNESS
#import "../SHDWHookSession.h"
#endif

#import <pthread.h>
#import <stdlib.h>
#import <string.h>

// Shared matcher for the two predicates below. `boundary` is the character
// that must follow a safe-mode name: '\0' for a bare name (getenv view), '='
// for the "NAME=value" entry form (*environ scans). DYLD_* covers
// INSERT_LIBRARIES and every search-path knob; the JAILBREAKD_* and safe-mode
// variables come from jailbreakd/loader launch contexts.
static BOOL shdw_env_hidden(const char *s, char boundary) {
  if (!s) {
    return NO;
  }

  if (strncmp(s, "DYLD_", 5) == 0 || strncmp(s, "JAILBREAKD_", 11) == 0) {
    return YES;
  }

  if ((strncmp(s, "_MSSafeMode", 11) == 0 && s[11] == boundary) ||
      (strncmp(s, "_SafeMode", 9) == 0 && s[9] == boundary) ||
      (strncmp(s, "_SubstituteSafeMode", 19) == 0 && s[19] == boundary) ||
      (strncmp(s, "BOOTSTRAP_PREFIX", 16) == 0 && s[16] == boundary)) {
    return YES;
  }

  return NO;
}

BOOL shdw_env_name_hidden(const char *name) {
  return shdw_env_hidden(name, '\0');
}

// Whole-entry policy for *environ scans: every dynamic-loader and
// jailbreakd-launch variable is dropped, not just the INSERT_LIBRARIES entry.
BOOL shdw_env_entry_hidden(const char *var) {
  return shdw_env_hidden(var, '=');
}

// Thread-local PATH storage for the getenv view. One thread can't overwrite
// another's value, and the returned pointer keeps getenv's documented
// lifetime (valid until the next getenv call on this thread).
static _Thread_local char *shdw_env_path_storage = NULL;
static _Thread_local size_t shdw_env_path_capacity = 0;

// Cached raw PATH input for shdw_env_sanitized_path: the split/join only
// reruns when the value differs from this thread's last-seen one. Thread-local
// like the output storage — a returned pointer keeps its per-thread lifetime,
// and the setenv/unsetenv hooks below only clear their own thread's entry (a
// changed PATH on any thread fails the input comparison and recomputes).
static _Thread_local char *shdw_env_path_cache_input = NULL;
static _Thread_local size_t shdw_env_path_cache_capacity = 0;

// _NSGetEnviron snapshot storage (shdw_env_filtered_snapshot) and the
// PROCARGS2 PATH-entry storage (shdw_procargs2_filter). File-scope rather than
// function-local so the thread-exit destructor below can free them: a
// per-thread realloc'd buffer left in a bare _Thread_local pointer leaks when
// the owning thread terminates (destroying the pointer slot does not free what
// it points at).
static _Thread_local char **shdw_env_snapshot_filtered = NULL;
static _Thread_local size_t shdw_env_snapshot_filtered_cap = 0;
static _Thread_local char *shdw_env_snapshot_path = NULL;
static _Thread_local size_t shdw_env_snapshot_path_cap = 0;
static _Thread_local char *shdw_env_procargs_path = NULL;
static _Thread_local size_t shdw_env_procargs_path_cap = 0;

// Thread-exit cleanup for the per-thread env buffers above. pthread destructors
// run on the terminating thread, so these file-scope _Thread_local pointers
// resolve to that thread's copies and can be freed directly. Long-lived threads
// (GCD workers) keep their peak buffers until exit either way — this reclaims
// buffers from threads that are actually torn down (thread-pool churn).
static pthread_key_t shdw_env_tls_key;
static pthread_once_t shdw_env_tls_once = PTHREAD_ONCE_INIT;
static int shdw_env_tls_key_error;

static void shdw_env_tls_destructor(void *unused) {
  (void)unused;

  free(shdw_env_path_storage);
  shdw_env_path_storage = NULL;
  shdw_env_path_capacity = 0;

  free(shdw_env_path_cache_input);
  shdw_env_path_cache_input = NULL;
  shdw_env_path_cache_capacity = 0;

  free(shdw_env_snapshot_filtered);
  shdw_env_snapshot_filtered = NULL;
  shdw_env_snapshot_filtered_cap = 0;

  free(shdw_env_snapshot_path);
  shdw_env_snapshot_path = NULL;
  shdw_env_snapshot_path_cap = 0;

  free(shdw_env_procargs_path);
  shdw_env_procargs_path = NULL;
  shdw_env_procargs_path_cap = 0;
}

static void shdw_env_tls_key_init(void) {
  shdw_env_tls_key_error =
      pthread_key_create(&shdw_env_tls_key, shdw_env_tls_destructor);
}

// Arm the destructor for this thread. Cheap and idempotent: the key value only
// needs to be non-NULL for the destructor to fire at thread exit. Register
// before allocating so failure cannot leave unowned buffers or touch an invalid
// key.
static BOOL shdw_env_tls_arm(void) {
  pthread_once(&shdw_env_tls_once, shdw_env_tls_key_init);

  if (shdw_env_tls_key_error) {
    return NO;
  }
  return pthread_getspecific(shdw_env_tls_key) ||
         pthread_setspecific(shdw_env_tls_key, (void *)1) == 0;
}

// Shared PATH component filter for every environment surface. The callers
// retain their distinct ownership/lifetime contracts; this only centralizes
// which components are hidden.
static NSString *shdw_env_filtered_path_string(NSString *value, BOOL *changed) {
  NSArray *parts = [value componentsSeparatedByString:@":"];
  NSMutableArray *kept = [NSMutableArray arrayWithCapacity:parts.count];

  for (NSString *part in parts) {
    // Empty components (e.g. "::" or an empty value) mean CWD on POSIX;
    // macOS Foundation throws on [@"": fileSystemRepresentation].
    if ([part length] == 0 ||
        !shdw_is_restricted_root_c([part fileSystemRepresentation])) {
      [kept addObject:part];
    }
  }

  *changed = kept.count != parts.count;
  return *changed ? [kept componentsJoinedByString:@":"] : value;
}

// Removes jailbreak components from a PATH value (/var/jb bootstrap and
// preboot roots — stock iOS PATH has neither). Returns the original pointer
// when nothing needed removing, otherwise a sanitized copy in thread-local
// storage. An unchanged PATH (same raw value as the last call) returns the
// cached sanitized result without re-splitting/re-joining.
char *shdw_env_sanitized_path(const char *value) {
  if (!value || !shdw_env_tls_arm()) {
    return (char *)value;
  }
  if (shdw_env_path_cache_input &&
      strcmp(value, shdw_env_path_cache_input) == 0) {
    return shdw_env_path_storage; // PATH unchanged: cached sanitized result
  }

  NSString *raw = [NSString stringWithUTF8String:value];
  if (!raw) {
    return (char *)value;
  }

  BOOL changed = NO;
  NSString *filtered = shdw_env_filtered_path_string(raw, &changed);
  size_t len = [filtered lengthOfBytesUsingEncoding:NSUTF8StringEncoding] + 1;

  if (len > shdw_env_path_capacity) {
    char *grown = realloc(shdw_env_path_storage, len);

    if (!grown) {
      // OOM: fall back to the original value rather than returning a
      // truncated path.
      return (char *)value;
    }

    shdw_env_path_storage = grown;
    shdw_env_path_capacity = len;
  }

  strcpy(shdw_env_path_storage, filtered.UTF8String);

  // Remember the raw input for the next call.
  size_t input_len = strlen(value) + 1;

  if (input_len > shdw_env_path_cache_capacity) {
    char *grown = realloc(shdw_env_path_cache_input, input_len);

    if (!grown) {
      free(shdw_env_path_cache_input);
      shdw_env_path_cache_input = NULL;
      shdw_env_path_cache_capacity = 0;
      return shdw_env_path_storage; // OOM: no caching, next call recomputes
    }

    shdw_env_path_cache_input = grown;
    shdw_env_path_cache_capacity = input_len;
  }

  strcpy(shdw_env_path_cache_input, value);
  return shdw_env_path_storage;
}

#ifndef SHADOW_TEST_HARNESS
// --- raw `environ` symbol filtering -----------------------------------------
//
// getenv/_NSGetEnviron/NSProcessInfo/PROCARGS2 all report a filtered view, but
// a detector that reads the raw `environ` data symbol directly (its import is
// a plain __DATA pointer, never routed through any of those functions) still
// sees the launch-time DYLD_INSERT_LIBRARIES / JAILBREAKD_* / safe-mode
// entries. Close that channel by REBINDING the `environ` import slot in
// external images to a Shadow-owned cell that points at a filtered copy of
// the array (see shdw_universal_envpolicy). The real libSystem `environ` is
// never mutated — Shadow's own reads and child-process spawns keep the true
// array (they resolve `environ` through ShadowCore's own import, which is not
// rebound: HookKit's fishhook rewrites importer slots, and calls inside the
// defining image / ShadowCore's own slot are covered separately below).
//
// Coherence with setenv/unsetenv/putenv: the real array can be reallocated by
// libc when it grows, so the filtered copy is rebuilt (and republished) after
// every mutation and lazily whenever the real array pointer changes.

// The real libSystem environ cell, captured before the rebind so Shadow's own
// code and the rebuild below always read the true array. Resolved via
// _NSGetEnviron() (returns &environ) at install.
static char ***shdw_real_environ_cell = NULL;

// Shadow-owned published cell: the value external importers' `environ` slot is
// rebound to point AT (the slot holds &shdw_env_published_array, so a reader
// dereferences it to get the filtered char** — exactly environ's shape).
char **shdw_env_published_array = NULL;

// Two fixed-capacity generation buffers for the filtered array. Never freed
// (an external importer may hold the published char** across a rebuild), so a
// swap publishes the inactive generation and leaves the other valid for any
// in-flight reader. Capacity is generous — a process's environ is tens of
// entries. Overflow truncates (fail-soft: a detector sees a short but
// clean env, never a jailbreak entry).
#define SHDW_ENV_MIRROR_CAP 512
static char *shdw_env_mirror_a[SHDW_ENV_MIRROR_CAP];
static char *shdw_env_mirror_b[SHDW_ENV_MIRROR_CAP];
static char **shdw_env_mirror_active =
    NULL; // which generation is live-being-built
static pthread_mutex_t shdw_env_mirror_lock = PTHREAD_MUTEX_INITIALIZER;

// PATH entry storage for the mirror (a sanitized "PATH=..." lives here, not in
// the real array). One slot: environ has a single PATH. Grown as needed.
static char *shdw_env_mirror_path = NULL;
static size_t shdw_env_mirror_path_cap = 0;

// Rebuild the filtered array from the real one and publish it. Serialized by
// the caller-held lock. The real array is the source of truth every time, so
// a mutation (setenv/putenv) or a realloc is always reflected.
static void shdw_env_rebuild_locked(void) {
  char **real = shdw_real_environ_cell ? *shdw_real_environ_cell : NULL;
  if (!real) {
    return;
  }

  // Build into whichever generation is NOT currently published, so an
  // in-flight reader of the published one never sees a torn buffer.
  char **dst = (shdw_env_mirror_active == shdw_env_mirror_a)
                   ? shdw_env_mirror_b
                   : shdw_env_mirror_a;

  size_t out = 0;
  for (size_t i = 0; real[i]; i++) {
    if (out >= SHDW_ENV_MIRROR_CAP - 1) {
      break; // fail-soft truncate (see cap note above)
    }

    if (shdw_env_entry_hidden(real[i])) {
      continue;
    }

    if (strncmp(real[i], "PATH=", 5) == 0) {
      char *sanitized = shdw_env_sanitized_path_entry(
          real[i], &shdw_env_mirror_path, &shdw_env_mirror_path_cap);
      dst[out++] = sanitized ? sanitized : real[i];
      continue;
    }

    // Unhidden entries share the real array's string storage — those
    // strings outlive any single rebuild (libc owns them for the
    // process), so pointing at them is safe.
    dst[out++] = real[i];
  }
  dst[out] = NULL;

  shdw_env_mirror_active = dst;
  // Publish pointer-last with a release store: an external slot points at
  // &shdw_env_published_array, so the reader's acquire load of it sees a
  // fully-built dst.
  __atomic_store_n(&shdw_env_published_array, dst, __ATOMIC_RELEASE);
}

// Public rebuild entry (also called after the mutator hooks). Idempotent.
void shdw_env_publish_filtered(void) {
  pthread_mutex_lock(&shdw_env_mirror_lock);
  shdw_env_rebuild_locked();
  pthread_mutex_unlock(&shdw_env_mirror_lock);
}

// The REAL, unfiltered environ array. Shadow's own code (child-process spawns
// that must propagate DYLD_INSERT_LIBRARIES to systemhook, etc.) reads this
// instead of the `environ` symbol — whose importer slot is rebound to the
// filtered copy in every image, ShadowCore included. Falls back to a NULL
// (empty) terminator array only if capture never ran (never in practice).
char **shdw_env_real(void) {
  static char *empty[1] = {NULL};
  return shdw_real_environ_cell ? *shdw_real_environ_cell : empty;
}

// Capture the real environ cell and publish the first filtered generation.
// Called once at install, before the rebind.
void shdw_env_capture_real_environ(char ***realCell) {
  if (!realCell) {
    return;
  }
  pthread_mutex_lock(&shdw_env_mirror_lock);
  shdw_real_environ_cell = realCell;
  shdw_env_rebuild_locked();
  pthread_mutex_unlock(&shdw_env_mirror_lock);
}

// setenv/unsetenv/putenv can change the value behind the getenv hook's PATH
// sanitization AND the raw-environ filtered copy. The input comparison above
// self-heals a changed value; these hooks clear this thread's cache entry so a
// setenv with the SAME content still forces a re-evaluation, and rebuild the
// published filtered array so a raw-environ reader stays coherent. (Only the
// calling thread's PATH cache entry is cleared; other threads' entries fail
// the input comparison on their next call.)
static void shdw_env_path_cache_invalidate(void) {
  free(shdw_env_path_cache_input);
  shdw_env_path_cache_input = NULL;
  shdw_env_path_cache_capacity = 0;
}

static int (*original_setenv)(const char *name, const char *value,
                              int overwrite);
static int replaced_setenv(const char *name, const char *value, int overwrite) {
  shdw_env_path_cache_invalidate();
  int result = original_setenv(name, value, overwrite);
  shdw_env_publish_filtered();
  return result;
}

static int (*original_unsetenv)(const char *name);
static int replaced_unsetenv(const char *name) {
  shdw_env_path_cache_invalidate();
  int result = original_unsetenv(name);
  shdw_env_publish_filtered();
  return result;
}

static int (*original_putenv)(char *string);
static int replaced_putenv(char *string) {
  shdw_env_path_cache_invalidate();
  int result = original_putenv(string);
  shdw_env_publish_filtered();
  return result;
}

// Installed with the envvar group (dylib.x, next to shadowhook_libc_envvar):
// keeps the PATH sanitization cache coherent with the live environment and the
// raw-`environ` filtered copy coherent with setenv/putenv mutations. The
// `environ` data-symbol rebind itself is driven from the syscall installer
// (next to _NSGetEnviron), where the rebind lane lives.
void shdw_universal_envpolicy(SHDWHookSession *hooks) {
  [hooks hookFunction:setenv
      withReplacement:replaced_setenv
            outOldPtr:(void **)&original_setenv];
  [hooks hookFunction:unsetenv
      withReplacement:replaced_unsetenv
            outOldPtr:(void **)&original_unsetenv];
  [hooks hookFunction:putenv
      withReplacement:replaced_putenv
            outOldPtr:(void **)&original_putenv];
}
#endif

// Sanitizes a "PATH=..." entry: jailbreak components dropped, other
// components preserved. Returns NULL when nothing needed removing (the
// caller keeps the original entry), otherwise a rebuilt entry in the
// caller's thread-local storage.
char *shdw_env_sanitized_path_entry(const char *var, char **storage,
                                    size_t *capacity) {
  if (!var || strncmp(var, "PATH=", 5) != 0 || var[5] == '\0') {
    return NULL;
  }

  NSString *path = [NSString stringWithUTF8String:var + 5];
  if (!path) {
    return NULL;
  }

  BOOL changed = NO;
  NSString *filtered = shdw_env_filtered_path_string(path, &changed);
  if (!changed) {
    return NULL;
  }

  NSString *joined = [@"PATH=" stringByAppendingString:filtered];
  size_t len = [joined lengthOfBytesUsingEncoding:NSUTF8StringEncoding] + 1;

  if (len > *capacity) {
    char *grown = realloc(*storage, len);

    if (!grown) {
      // OOM: keep the original entry rather than a truncated path.
      return NULL;
    }

    *storage = grown;
    *capacity = len;
  }

  strcpy(*storage, joined.UTF8String);
  return *storage;
}

NSDictionary *shdw_env_sanitized_dictionary(NSDictionary *result) {
  NSMutableDictionary *filtered_result = [result mutableCopy];

  // Stock iOS never has these set; their presence is the jailbreak signal
  // a detector reads back from the cached environment. Driven by the same name
  // predicate every other channel uses (getenv, the *environ views, the
  // KERN_PROCARGS2 payload) so the sets cannot drift apart again — this list
  // had already lost BOOTSTRAP_PREFIX, which getenv() hid and this dictionary
  // still returned.
  for (NSString *key in [filtered_result allKeys]) {
    if (shdw_env_name_hidden([key UTF8String])) {
      [filtered_result removeObjectForKey:key];
    }
  }

  // PATH: drop jailbreak components, preserving everything else.
  NSString *pathValue = filtered_result[@"PATH"];

  if (pathValue && pathValue.length > 0) {
    BOOL changed = NO;
    NSString *filtered = shdw_env_filtered_path_string(pathValue, &changed);

    if (changed) {
      filtered_result[@"PATH"] = filtered;
    }
  }

  return filtered_result;
}

NSArray<NSString *> *shdw_env_sanitized_argv(NSArray<NSString *> *result) {
  NSMutableArray<NSString *> *filtered_result =
      [NSMutableArray arrayWithCapacity:result.count];

  // argv[0] and ordering are preserved; only injection flags (with their
  // path value) and restricted-path arguments are removed.
  [filtered_result addObject:result[0]];

  for (NSUInteger i = 1; i < result.count; i++) {
    NSString *arg = result[i];

    if ([arg isEqualToString:@"-dylib"] || [arg isEqualToString:@"-insert"] ||
        [arg isEqualToString:@"-load"] || [arg isEqualToString:@"-bundle"] ||
        [arg isEqualToString:@"-init"]) {
      // Injection flag: drop the flag and its following path value.
      if (i + 1 < result.count) {
        i++;
      }

      continue;
    }

    // Arbitrary argument values are not paths. Resolving them against a
    // restricted current directory would erase benign flags/values.
    if ([arg isAbsolutePath] && [_shadow isPathRestricted:arg]) {
      continue;
    }

    [filtered_result addObject:arg];
  }

  return filtered_result;
}

// _NSGetEnviron: returns the ADDRESS of the caller's environ variable, so
// the hook must hand out a pointer to OUR OWN filtered snapshot — libc's
// environ pointer is never modified (callers may write through the returned
// pointer; ours is private storage).
char ***shdw_env_filtered_snapshot(char **raw) {
  if (!raw || !shdw_env_tls_arm()) {
    return NULL;
  }

  size_t count = 0;

  while (raw[count]) {
    count++;
  }

  // Thread-local snapshot: concurrent realloc of a static buffer (two
  // threads calling _NSGetEnviron at once) is a use-after-free. The
  // returned pointer follows getenv-style per-thread lifetime semantics —
  // valid until this thread's next call — which is what callers expect.
  // Buffers are file-scope so the thread-exit destructor frees them.
  char **filtered = shdw_env_snapshot_filtered;
  char *path_entry_storage = shdw_env_snapshot_path;
  size_t path_entry_capacity = shdw_env_snapshot_path_cap;

  if (shdw_env_snapshot_filtered_cap < count + 1) {
    char **grown = realloc(filtered, (count + 1) * sizeof(char *));

    if (!grown) {
      return NULL;
    }

    filtered = grown;
    shdw_env_snapshot_filtered = grown;
    shdw_env_snapshot_filtered_cap = count + 1;
  }

  size_t out = 0;

  for (size_t i = 0; i < count; i++) {
    if (shdw_env_entry_hidden(raw[i])) {
      continue;
    }

    if (strncmp(raw[i], "PATH=", 5) == 0) {
      char *sanitized = shdw_env_sanitized_path_entry(
          raw[i], &path_entry_storage, &path_entry_capacity);

      // The sanitizer may have realloc'd the PATH storage; persist the
      // (possibly moved) pointer/capacity so the destructor frees it and
      // the next call reuses it.
      shdw_env_snapshot_path = path_entry_storage;
      shdw_env_snapshot_path_cap = path_entry_capacity;

      if (sanitized) {
        filtered[out++] = sanitized;
        continue;
      }
    }

    filtered[out++] = raw[i];
  }

  filtered[out] = NULL;

  // Return the address of the file-scope thread-local pointer, not a local:
  // callers dereference this to get the char** (environ shape), and it must
  // stay valid until this thread's next call.
  return &shdw_env_snapshot_filtered;
}

// KERN_PROCARGS2 payload filter (self pid).
//
// Payload layout, straight from xnu's sysctl_procargsx (bsd/kern/kern_sysctl.c:
// the argc word, then the copied stack string area — no pointer array anywhere,
// which is what this filter used to assume, so it never matched a real payload
// and the launch environment stayed readable):
//
//   [int argc][exec_path\0][NUL alignment padding]
//   [argc argument strings][environment strings]
//
// Every string NUL-terminated and contiguous to the end of the buffer; the
// kernel pads the bare exec path with extra NULs. A consumer walks argc strings
// after the padding (argv[0] first) and treats the rest as the environment.
// The kernel view carries the launch-time injection flags and the unfiltered
// environment while -[NSProcessInfo arguments] / getenv() / _NSGetEnviron()
// report the filtered view — a detector comparing the two channels sees the
// contradiction. When the views differ, the strings are compacted in place with
// the SAME drop rules as those hooks: injection flags (with their value),
// restricted path arguments, DYLD_*/JAILBREAKD_*/safe-mode/BOOTSTRAP_PREFIX env
// entries and jailbreak PATH components. PATH is written back over its own
// bytes (the sanitized value is always shorter, so the payload never grows) and
// *oldlenp shrinks by the bytes removed. Malformed payloads pass through
// untouched.
void shdw_procargs2_filter(void *oldp, size_t *oldlenp) {
  @autoreleasepool {
    if (!oldp || !oldlenp) {
      return;
    }

    size_t len = *oldlenp;
    char *base = (char *)oldp;

    if (len < sizeof(int) + 2) {
      return;
    }

    int argc = ((int *)base)[0];

    if (argc < 0) {
      return;
    }

    char *cur = base + sizeof(int);
    char *end = base + len;

    // Exec path, then its alignment padding. Shape-refuse anything the kernel
    // never emits: an unterminated path, an empty one, or a relative one (the
    // kernel always writes the absolute path of the executable). Refusing is
    // the pre-fix behaviour for payloads this filter does not model, which is
    // the safe direction — the alternative would be compacting bytes whose
    // layout we only guessed.
    size_t exec_len = strnlen(cur, (size_t)(end - cur));

    if (cur + exec_len >= end || exec_len == 0 || cur[0] != '/') {
      return;
    }

    cur += exec_len + 1;

    while (cur < end && *cur == '\0') {
      cur++;
    }

    if (cur >= end) {
      return;
    }

    // ---- argv drop decisions (mirrors -[NSProcessInfo arguments]) ----
    // Two passes: dropping an injection flag also drops the value string that
    // follows it, and the compaction below must not have to reason about that
    // while it moves bytes.
    BOOL *keep = NULL;

    if (argc > 0) {
      keep = (BOOL *)calloc((size_t)argc, sizeof(BOOL));

      if (!keep) {
        return;
      }
    }

    char *argv_start = cur;
    int seen = 0;

    while (seen < argc && cur < end) {
      char *a = cur;
      size_t a_len = strnlen(a, (size_t)(end - a));

      if (a + a_len >= end) {
        break; // unterminated argument: not a payload we understand
      }

      cur = a + a_len + 1;

      if ([_shadow isCPathRestricted:a]) {
        seen++;
        continue; // restricted path argument: drop
      }

      if (strcmp(a, "-dylib") == 0 || strcmp(a, "-insert") == 0 ||
          strcmp(a, "-load") == 0 || strcmp(a, "-bundle") == 0 ||
          strcmp(a, "-init") == 0) {
        if (seen + 1 < argc) {
          char *value = cur;
          size_t value_len = strnlen(value, (size_t)(end - value));

          if (value + value_len >= end) {
            break;
          }

          cur = value + value_len + 1;
          seen++; // drop the flag's value slot as well
        }

        seen++;
        continue;
      }

      keep[seen] = YES;
      seen++;
    }

    if (seen != argc) {
      // The payload does not hold the argc strings its own header claims.
      free(keep);
      return;
    }

    // ---- compact argv (write cursor trails the read cursor) ----
    char *w = argv_start;
    char *r = argv_start;
    int new_argc = 0;

    for (int i = 0; i < argc; i++) {
      char *a = r;
      size_t a_len = strnlen(a, (size_t)(end - a));

      r = a + a_len + 1;

      if (!keep[i]) {
        continue;
      }

      if (w != a) {
        memmove(w, a, a_len + 1);
      }

      w += a_len + 1;
      new_argc++;
    }

    // ---- environment (mirrors getenv/_NSGetEnviron) ----
    char *path_entry_storage = shdw_env_procargs_path;
    size_t path_entry_capacity = shdw_env_procargs_path_cap;

    while (r < end) {
      char *e = r;
      size_t e_len = strnlen(e, (size_t)(end - e));

      if (e + e_len >= end) {
        // Unterminated tail: keep it verbatim, there is nothing to classify.
        memmove(w, e, (size_t)(end - e));
        w += (size_t)(end - e);
        break;
      }

      r = e + e_len + 1;

      if (shdw_env_entry_hidden(e)) {
        continue;
      }

      const char *out = e;

      if (strncmp(e, "PATH=", 5) == 0 && e[5] && shdw_env_tls_arm()) {
        // Same sanitizer as the getenv/_NSGetEnviron PATH hooks; the rebuilt
        // entry lands in the caller's thread-local storage.
        char *sanitized = shdw_env_sanitized_path_entry(e, &path_entry_storage,
                                                        &path_entry_capacity);

        // Persist the (possibly realloc'd) storage even when nothing changed,
        // so the thread-exit destructor frees it and the next call reuses it.
        shdw_env_procargs_path = path_entry_storage;
        shdw_env_procargs_path_cap = path_entry_capacity;

        if (sanitized) {
          out = sanitized;
        }
      }

      size_t out_len = strlen(out);

      memmove(w, out, out_len + 1);
      w += out_len + 1;
    }

    ((int *)base)[0] = new_argc;
    *oldlenp = (size_t)(w - base);

    free(keep);
  }
}
