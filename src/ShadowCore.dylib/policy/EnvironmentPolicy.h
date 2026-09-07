// Plugin: Policy_Environment — registered in SHDWPluginRegistry (HookConfiguration.m)
#define SHDWPolicyEnvironmentPluginID "Policy_Environment"

// Environment sanitization policy — the single source for how environment
// data is filtered for external callers across every surface that exposes
// it: getenv, *environ/_NSGetEnviron, -[NSProcessInfo environment/arguments]
// and the KERN_PROCARGS2 payload. All of those channels must agree, or a
// detector comparing two of them sees the contradiction.
//
// None of these classify callers — the isCallerExternal() gate stays at the
// hook sites (adapters in hooks/). nil/NULL inputs pass through unchanged,
// and no function here ever mutates a caller's storage except the
// documented in-place KERN_PROCARGS2 rebuild.

#import <Foundation/Foundation.h>

// True when `name` is a hidden environment variable (getenv view; bare
// name, no '='): DYLD_*/JAILBREAKD_* prefixes and the safe-mode flags.
BOOL shdw_env_name_hidden(const char* name);

// True when a whole *environ entry ("NAME=value") must be dropped: the
// getenv rule applied to the entry form (stocks' launch-time injection and
// safe-mode variables).
BOOL shdw_env_entry_hidden(const char* var);

// PATH value sanitizer (getenv view): drops jailbreak PATH components
// (/var/jb bootstrap and preboot roots — stock iOS PATH has neither),
// preserving everything else. Returns the ORIGINAL pointer when nothing
// needed removing, otherwise a sanitized copy in thread-local storage
// (getenv-lifetime semantics: valid until this thread's next call).
char* shdw_env_sanitized_path(const char* value);

// Entry-form PATH sanitizer for *environ scans: the same component rule on
// a full "PATH=..." entry. Returns NULL when the entry is unchanged (or not
// a PATH entry with a value); the rebuilt entry is written to *storage
// (caller-owned thread-local storage, grown through *capacity).
char* shdw_env_sanitized_path_entry(const char* var, char** storage, size_t* capacity);

// NSProcessInfo.environment view: hidden keys removed and PATH components
// sanitized, in a new mutable dictionary. (The hook calls this only for
// external callers with a non-nil result.)
NSDictionary* shdw_env_sanitized_dictionary(NSDictionary* result);

// -[NSProcessInfo arguments] view: argv[0] and ordering are preserved; only
// injection flags (with their path value) and restricted-path arguments are
// removed. (The hook calls this only for external callers with a non-empty
// result.)
NSArray<NSString*>* shdw_env_sanitized_argv(NSArray<NSString*>* result);

// _NSGetEnviron view: returns a pointer to this thread's filtered snapshot
// of `raw` (a NULL-terminated char* array — the caller passes `environ`).
// The snapshot is rebuilt on every call so variables added by setenv since
// the last call stay visible; the returned pointer stays valid until this
// thread's next call. Returns NULL on OOM — the caller falls back to the
// unfiltered view.
char*** shdw_env_filtered_snapshot(char** raw);

// Raw `environ` data-symbol filtering. External importers' `environ` slot is
// rebound to point at shdw_env_published_array, a Shadow-owned cell holding a
// filtered copy of the real array (hidden DYLD_*/JAILBREAKD_*/safe-mode
// entries dropped, PATH jailbreak components stripped). The real libSystem
// `environ` is never mutated; Shadow's own reads and child spawns keep truth.
//
//   shdw_env_capture_real_environ  — capture &environ and publish generation 0
//                                     (call once at install, before the rebind)
//   shdw_env_publish_filtered      — rebuild+republish after a setenv/putenv
//   shdw_env_published_array       — the filtered char** the slot points at
extern char** shdw_env_published_array;
void shdw_env_capture_real_environ(char*** realCell);
void shdw_env_publish_filtered(void);
// The real, unfiltered environ (Shadow's own reads / child spawns): the
// `environ` symbol is rebound process-wide to the filtered copy, so internal
// callers that need the true array (with DYLD_INSERT_LIBRARIES for systemhook)
// must call this instead of referencing `environ`.
char** shdw_env_real(void);

// KERN_PROCARGS2 (self pid) payload filter: the kernel payload encodes
// [int argc][char* argv[argc+1]][char* envp...][strings blob] with argv/envp
// pointers referencing the strings blob. The kernel view carries the
// launch-time injection flags and the unfiltered environment while
// NSProcessInfo/getenv/_NSGetEnviron report the filtered view; when the
// views differ the payload is rebuilt in place with the SAME drop rules as
// those hooks. Malformed payloads pass through untouched.
void shdw_procargs2_filter(void* oldp, size_t* oldlenp);