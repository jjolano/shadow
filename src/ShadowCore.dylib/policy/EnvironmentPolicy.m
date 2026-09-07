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

#import <string.h>
#import <stdlib.h>
#import <pthread.h>

BOOL shdw_env_name_hidden(const char* name) {
    if(!name) {
        return NO;
    }

    // DYLD_* covers INSERT_LIBRARIES and every search-path knob; the
    // JAILBREAKD_* and safe-mode variables come from jailbreakd/loader
    // launch contexts.
    if(strncmp(name, "DYLD_", 5) == 0 || strncmp(name, "JAILBREAKD_", 11) == 0) {
        return YES;
    }

    if(strcmp(name, "_MSSafeMode") == 0
    || strcmp(name, "_SafeMode") == 0
    || strcmp(name, "_SubstituteSafeMode") == 0) {
        return YES;
    }

    return NO;
}

BOOL shdw_env_entry_hidden(const char* var) {
    if(!var) {
        return NO;
    }

    // Whole-entry policy for *environ scans: every dynamic-loader and
    // jailbreakd-launch variable is dropped, not just the INSERT_LIBRARIES
    // entry. Entries carry the "NAME=value" form, so the safe-mode flags
    // match with the trailing '='.
    if(strncmp(var, "DYLD_", 5) == 0 || strncmp(var, "JAILBREAKD_", 11) == 0) {
        return YES;
    }

    if(strncmp(var, "_MSSafeMode=", 12) == 0
    || strncmp(var, "_SafeMode=", 10) == 0
    || strncmp(var, "_SubstituteSafeMode=", 20) == 0) {
        return YES;
    }

    return NO;
}

// Thread-local PATH storage for the getenv view. One thread can't overwrite
// another's value, and the returned pointer keeps getenv's documented
// lifetime (valid until the next getenv call on this thread).
static _Thread_local char* shdw_env_path_storage = NULL;
static _Thread_local size_t shdw_env_path_capacity = 0;

// Cached raw PATH input for shdw_env_sanitized_path: the split/join only
// reruns when the value differs from this thread's last-seen one. Thread-local
// like the output storage — a returned pointer keeps its per-thread lifetime,
// and the setenv/unsetenv hooks below only clear their own thread's entry (a
// changed PATH on any thread fails the input comparison and recomputes).
static _Thread_local char* shdw_env_path_cache_input = NULL;
static _Thread_local size_t shdw_env_path_cache_capacity = 0;

// Shared PATH component filter for every environment surface. The callers
// retain their distinct ownership/lifetime contracts; this only centralizes
// which components are hidden.
static NSString* shdw_env_filtered_path_string(NSString* value, BOOL* changed) {
    NSArray* parts = [value componentsSeparatedByString:@":"];
    NSMutableArray* kept = [NSMutableArray arrayWithCapacity:parts.count];

    for(NSString* part in parts) {
        // Empty components (e.g. "::" or an empty value) mean CWD on POSIX;
        // macOS Foundation throws on [@"": fileSystemRepresentation].
        if([part length] == 0 ||
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
char* shdw_env_sanitized_path(const char* value) {
    if(value && shdw_env_path_cache_input && strcmp(value, shdw_env_path_cache_input) == 0) {
        return shdw_env_path_storage;  // PATH unchanged: cached sanitized result
    }

    NSString* raw = [NSString stringWithUTF8String:value];
    if(!raw) {
        return (char *)value;
    }

    BOOL changed = NO;
    NSString* filtered = shdw_env_filtered_path_string(raw, &changed);
    size_t len = [filtered lengthOfBytesUsingEncoding:NSUTF8StringEncoding] + 1;

    if(len > shdw_env_path_capacity) {
        char* grown = realloc(shdw_env_path_storage, len);

        if(!grown) {
            // OOM: fall back to the original value rather than returning a
            // truncated path.
            return (char *) value;
        }

        shdw_env_path_storage = grown;
        shdw_env_path_capacity = len;
    }

    strcpy(shdw_env_path_storage, filtered.UTF8String);

    // Remember the raw input for the next call.
    size_t input_len = strlen(value) + 1;

    if(input_len > shdw_env_path_cache_capacity) {
        char* grown = realloc(shdw_env_path_cache_input, input_len);

        if(!grown) {
            return shdw_env_path_storage;  // OOM: no caching, next call recomputes
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
static char*** shdw_real_environ_cell = NULL;

// Shadow-owned published cell: the value external importers' `environ` slot is
// rebound to point AT (the slot holds &shdw_env_published_array, so a reader
// dereferences it to get the filtered char** — exactly environ's shape).
char** shdw_env_published_array = NULL;

// Two fixed-capacity generation buffers for the filtered array. Never freed
// (an external importer may hold the published char** across a rebuild), so a
// swap publishes the inactive generation and leaves the other valid for any
// in-flight reader. Capacity is generous — a process's environ is tens of
// entries. Overflow truncates (fail-soft: a detector sees a short but
// clean env, never a jailbreak entry).
#define SHDW_ENV_MIRROR_CAP 512
static char* shdw_env_mirror_a[SHDW_ENV_MIRROR_CAP];
static char* shdw_env_mirror_b[SHDW_ENV_MIRROR_CAP];
static char** shdw_env_mirror_active = NULL;   // which generation is live-being-built
static pthread_mutex_t shdw_env_mirror_lock = PTHREAD_MUTEX_INITIALIZER;

// PATH entry storage for the mirror (a sanitized "PATH=..." lives here, not in
// the real array). One slot: environ has a single PATH. Grown as needed.
static char* shdw_env_mirror_path = NULL;
static size_t shdw_env_mirror_path_cap = 0;

// Rebuild the filtered array from the real one and publish it. Serialized by
// the caller-held lock. The real array is the source of truth every time, so
// a mutation (setenv/putenv) or a realloc is always reflected.
static void shdw_env_rebuild_locked(void) {
    char** real = shdw_real_environ_cell ? *shdw_real_environ_cell : NULL;
    if(!real) {
        return;
    }

    // Build into whichever generation is NOT currently published, so an
    // in-flight reader of the published one never sees a torn buffer.
    char** dst = (shdw_env_mirror_active == shdw_env_mirror_a)
        ? shdw_env_mirror_b : shdw_env_mirror_a;

    size_t out = 0;
    for(size_t i = 0; real[i]; i++) {
        if(out >= SHDW_ENV_MIRROR_CAP - 1) {
            break;  // fail-soft truncate (see cap note above)
        }

        if(shdw_env_entry_hidden(real[i])) {
            continue;
        }

        if(strncmp(real[i], "PATH=", 5) == 0) {
            char* sanitized = shdw_env_sanitized_path_entry(real[i],
                &shdw_env_mirror_path, &shdw_env_mirror_path_cap);
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
char** shdw_env_real(void) {
    static char* empty[1] = { NULL };
    return shdw_real_environ_cell ? *shdw_real_environ_cell : empty;
}

// Capture the real environ cell and publish the first filtered generation.
// Called once at install, before the rebind.
void shdw_env_capture_real_environ(char*** realCell) {
    if(!realCell) {
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
    if(shdw_env_path_cache_input) {
        shdw_env_path_cache_input[0] = '\0';
    }
}

static int (*original_setenv)(const char* name, const char* value, int overwrite);
static int replaced_setenv(const char* name, const char* value, int overwrite) {
    shdw_env_path_cache_invalidate();
    int result = original_setenv(name, value, overwrite);
    shdw_env_publish_filtered();
    return result;
}

static int (*original_unsetenv)(const char* name);
static int replaced_unsetenv(const char* name) {
    shdw_env_path_cache_invalidate();
    int result = original_unsetenv(name);
    shdw_env_publish_filtered();
    return result;
}

static int (*original_putenv)(char* string);
static int replaced_putenv(char* string) {
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
void shdw_universal_envpolicy(SHDWHookSession* hooks) {
    [hooks hookFunction:setenv withReplacement:replaced_setenv outOldPtr:(void **) &original_setenv];
    [hooks hookFunction:unsetenv withReplacement:replaced_unsetenv outOldPtr:(void **) &original_unsetenv];
    [hooks hookFunction:putenv withReplacement:replaced_putenv outOldPtr:(void **) &original_putenv];
}
#endif

// Sanitizes a "PATH=..." entry: jailbreak components dropped, other
// components preserved. Returns NULL when nothing needed removing (the
// caller keeps the original entry), otherwise a rebuilt entry in the
// caller's thread-local storage.
char* shdw_env_sanitized_path_entry(const char* var, char** storage, size_t* capacity) {
    if(!var || strncmp(var, "PATH=", 5) != 0 || var[5] == '\0') {
        return NULL;
    }

    NSString* path = [NSString stringWithUTF8String:var + 5];
    if(!path) {
        return NULL;
    }

    BOOL changed = NO;
    NSString* filtered = shdw_env_filtered_path_string(path, &changed);
    if(!changed) {
        return NULL;
    }

    NSString* joined = [@"PATH=" stringByAppendingString:filtered];
    size_t len = [joined lengthOfBytesUsingEncoding:NSUTF8StringEncoding] + 1;

    if(len > *capacity) {
        char* grown = realloc(*storage, len);

        if(!grown) {
            // OOM: keep the original entry rather than a truncated path.
            return NULL;
        }

        *storage = grown;
        *capacity = len;
    }

    strcpy(*storage, joined.UTF8String);
    return *storage;
}

NSDictionary* shdw_env_sanitized_dictionary(NSDictionary* result) {
    NSMutableDictionary* filtered_result = [result mutableCopy];

    // Stock iOS never has these set; their presence is the jailbreak signal
    // a detector reads back from the cached environment (same set as the
    // getenv/*environ views).
    for(NSString* key in [filtered_result allKeys]) {
        if([key hasPrefix:@"DYLD_"]
        || [key hasPrefix:@"JAILBREAKD_"]
        || [key isEqualToString:@"_MSSafeMode"]
        || [key isEqualToString:@"_SafeMode"]
        || [key isEqualToString:@"_SubstituteSafeMode"]) {
            [filtered_result removeObjectForKey:key];
        }
    }

    // PATH: drop jailbreak components, preserving everything else.
    NSString* pathValue = filtered_result[@"PATH"];

    if(pathValue && pathValue.length > 0) {
        BOOL changed = NO;
        NSString* filtered = shdw_env_filtered_path_string(pathValue, &changed);

        if(changed) {
            filtered_result[@"PATH"] = filtered;
        }
    }

    return filtered_result;
}

NSArray<NSString*>* shdw_env_sanitized_argv(NSArray<NSString*>* result) {
    NSMutableArray<NSString*>* filtered_result = [NSMutableArray arrayWithCapacity:result.count];

    // argv[0] and ordering are preserved; only injection flags (with their
    // path value) and restricted-path arguments are removed.
    [filtered_result addObject:result[0]];

    for(NSUInteger i = 1; i < result.count; i++) {
        NSString* arg = result[i];

        if([arg isEqualToString:@"-dylib"]
        || [arg isEqualToString:@"-insert"]
        || [arg isEqualToString:@"-load"]
        || [arg isEqualToString:@"-bundle"]
        || [arg isEqualToString:@"-init"]) {
            // Injection flag: drop the flag and its following path value.
            if(i + 1 < result.count) {
                i++;
            }

            continue;
        }

        // Arbitrary argument values are not paths. Resolving them against a
        // restricted current directory would erase benign flags/values.
        if([arg isAbsolutePath] && [_shadow isPathRestricted:arg]) {
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
char*** shdw_env_filtered_snapshot(char** raw) {
    if(!raw) {
        return NULL;
    }

    size_t count = 0;

    while(raw[count]) {
        count++;
    }

    // Thread-local snapshot: concurrent realloc of a static buffer (two
    // threads calling _NSGetEnviron at once) is a use-after-free. The
    // returned pointer follows getenv-style per-thread lifetime semantics —
    // valid until this thread's next call — which is what callers expect.
    static _Thread_local char** filtered = NULL;
    static _Thread_local size_t filtered_capacity = 0;
    static _Thread_local char* path_entry_storage = NULL;
    static _Thread_local size_t path_entry_capacity = 0;

    if(filtered_capacity < count + 1) {
        char** grown = realloc(filtered, (count + 1) * sizeof(char *));

        if(!grown) {
            return NULL;
        }

        filtered = grown;
        filtered_capacity = count + 1;
    }

    size_t out = 0;

    for(size_t i = 0; i < count; i++) {
        if(shdw_env_entry_hidden(raw[i])) {
            continue;
        }

        if(strncmp(raw[i], "PATH=", 5) == 0) {
            char* sanitized = shdw_env_sanitized_path_entry(raw[i], &path_entry_storage, &path_entry_capacity);

            if(sanitized) {
                filtered[out++] = sanitized;
                continue;
            }
        }

        filtered[out++] = raw[i];
    }

    filtered[out] = NULL;

    return &filtered;
}

// KERN_PROCARGS2 payload filter (self pid): the kernel payload encodes
// [int argc][char* argv[argc+1]][char* envp...][strings blob], argv/envp
// pointers referencing the strings blob. The kernel view carries the
// launch-time injection flags and the unfiltered environment while
// -[NSProcessInfo arguments] / getenv() / _NSGetEnviron() report the
// filtered view — a detector comparing the two channels sees the
// contradiction. When the views differ, the payload is rebuilt in place with
// the SAME drop rules as those hooks: injection flags (with their value),
// restricted paths, DYLD_*/JAILBREAKD_*/safe-mode env entries and jailbreak
// PATH components. The strings blob is memmoved down, every kept pointer
// into it is shifted by the compaction amount, and a sanitized PATH= entry
// is written in place when it changed. Malformed payloads pass through
// untouched.
void shdw_procargs2_filter(void* oldp, size_t* oldlenp) {
    @autoreleasepool {
        if(!oldp || !oldlenp) {
            return;
        }

        size_t len = *oldlenp;
        char* base = (char *) oldp;

        if(len < sizeof(int) + sizeof(char *)) {
            return;
        }

        int argc = ((int *) base)[0];
        char** argv = (char **) (base + sizeof(int));

        if(argc <= 0) {
            return;
        }

        size_t argv_slots = (size_t) argc + 1;

        if(sizeof(int) + argv_slots * sizeof(char *) + sizeof(char *) > len) {
            return;  // no room for the envp terminator: malformed
        }

        char** envp = argv + argv_slots;
        size_t envp_count = 0;
        size_t max_env = (len - (sizeof(int) + argv_slots * sizeof(char *))) / sizeof(char *);

        while(envp_count < max_env && envp[envp_count] != NULL) {
            envp_count++;
        }

        if(envp_count == max_env) {
            return;  // envp terminator missing from the payload: malformed
        }

        char* blob_start = (char *) envp + (envp_count + 1) * sizeof(char *);
        char* blob_end = base + len;

        // ---- argv drop decisions (mirrors -[NSProcessInfo arguments]) ----
        BOOL* keep = (BOOL *) calloc((size_t) argc, sizeof(BOOL));

        if(!keep) {
            return;
        }

        int new_argc = 0;

        for(int i = 0; i < argc; i++) {
            char* a = argv[i];

            if(a == NULL || a < blob_start || a >= blob_end) {
                keep[i] = YES;  // NULL or unclassifiable: keep
                new_argc++;
                continue;
            }

            if([_shadow isCPathRestricted:a]) {
                continue;  // restricted path argument: drop
            }

            if(strcmp(a, "-dylib") == 0 || strcmp(a, "-insert") == 0 || strcmp(a, "-load") == 0
            || strcmp(a, "-bundle") == 0 || strcmp(a, "-init") == 0) {
                if(i + 1 < argc) {
                    i++;  // drop the flag's value slot as well
                }

                continue;
            }

            keep[i] = YES;
            new_argc++;
        }

        // ---- env entries (mirrors getenv/_NSGetEnviron) ----
        char** env_keep = (char **) malloc((envp_count + 1) * sizeof(char *));

        if(!env_keep) {
            free(keep);
            return;
        }

        size_t eout = 0;
        char* sanitized_path = NULL;
        char* path_blob_ptr = NULL;  // blob pointer of the (single) PATH entry
        static _Thread_local char* path_entry_storage = NULL;
        static _Thread_local size_t path_entry_capacity = 0;

        for(size_t i = 0; i < envp_count; i++) {
            char* e = envp[i];

            if(e == NULL || e < blob_start || e >= blob_end) {
                continue;
            }

            if(shdw_env_entry_hidden(e)) {
                continue;
            }

            if(strncmp(e, "PATH=", 5) == 0 && e[5]) {
                // Rewrite the PATH entry in place (same sanitizer as the
                // getenv/_NSGetEnviron PATH hooks). The sanitized value is
                // always SHORTER than the original, so it fits where the
                // original string lives inside the blob — no payload
                // growth, pointer stays at its (shifted) blob location.
                char* sanitized = shdw_env_sanitized_path_entry(e, &path_entry_storage, &path_entry_capacity);

                if(sanitized) {
                    sanitized_path = sanitized;
                    path_blob_ptr = e;
                }

                env_keep[eout++] = e;
                continue;
            }

            env_keep[eout++] = e;
        }

        size_t new_envp_count = eout;

        // ---- rebuild geometry ----
        size_t new_arrays_end = sizeof(int) + ((size_t) new_argc + 1 + new_envp_count + 1) * sizeof(char *);
        size_t old_blob_off = sizeof(int) + (argv_slots + envp_count + 1) * sizeof(char *);

        if(new_arrays_end > old_blob_off) {
            // Arrays only shrink when dropping entries; never grow the payload.
            free(keep);
            free(env_keep);
            return;
        }

        ptrdiff_t shift = (ptrdiff_t)(old_blob_off - new_arrays_end);

        if(shift == 0 && !sanitized_path) {
            free(keep);
            free(env_keep);
            return;  // the payload already agrees with the filtered view
        }

        // ---- write back (all reads below are from captured state) ----
        ((int *) base)[0] = new_argc;

        char** dst = argv;

        for(int i = 0; i < argc; i++) {
            if(keep[i]) {
                *dst++ = argv[i] ? argv[i] - shift : NULL;
            }
        }

        *dst = NULL;
        dst++;

        for(size_t i = 0; i < new_envp_count; i++) {
            *dst++ = env_keep[i] - shift;  // all entries live in the blob
        }

        *dst = NULL;

        if(shift > 0) {
            memmove(base + new_arrays_end, base + old_blob_off, len - old_blob_off);
        }

        if(sanitized_path && path_blob_ptr) {
            // Rewrite the PATH entry in its (moved) blob location. The value
            // is shorter than the original that occupied this space, so the
            // write stays inside the payload.
            strcpy(path_blob_ptr - shift, sanitized_path);
        }

        *oldlenp = new_arrays_end + (len - old_blob_off);

        free(keep);
        free(env_keep);
    }
}
