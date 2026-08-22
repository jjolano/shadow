// Host test-container shim (Linux builds).
//
// Two jobs, both no-ops or absent on Darwin (where the real dyld provides
// the symbols and the engine's literal /var/jb gates work against a real
// jailbreak):
//
// 1. Virtual filesystem: the engine's rootless existence gates call the C
//    functions access() and realpath() with LITERAL "/var/jb"-prefixed
//    paths (Core.m builds them directly — they never round-trip through
//    RootBridge). On a host there is no /var/jb, so those gates could never
//    pass. The harness links with -Wl,--wrap=access -Wl,--wrap=realpath,
//    which redirects every call in the binary to __wrap_* below; the
//    wrappers rewrite "/var/jb..." to a fixture jbroot directory on disk,
//    so the gates behave exactly as on a rootless device (file present →
//    gate passes → engine decides; absent → gate blocks). Everything else
//    passes through to the real libc functions. This is the "testcontainer
//    that mimics a filesystem".
//
// 2. dyld_image_path_containing_address stub: referenced by -[Shadow
//    isAddrRestricted:], which the harness never calls; a NULL return is
//    correct and harmless. (_NSGetArgv is deliberately NOT stubbed —
//    libgnustep-base exports its own, and a duplicate would interpose
//    GNUstep's internal argv handling before any harness setup.)
//
// Only one buffer (thread-local) is used for mapping: the engine is
// single-threaded in the harness (no hooked hook threads).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>

#if defined(__linux__)

static char gJBPath[PATH_MAX]; // absolute fixture jbroot; empty = disabled

extern int __real_access(const char* path, int mode);
extern char* __real_realpath(const char* path, char* resolved);
extern int __real_open(const char* path, int flags, ...);

void shdw_fs_set_jbroot(const char* jbroot) {
    gJBPath[0] = '\0';

    if(jbroot && jbroot[0]) {
        char resolved[PATH_MAX];

        // __real_realpath: the wrap would otherwise recurse.
        if(__real_realpath(jbroot, resolved)) {
            snprintf(gJBPath, sizeof gJBPath, "%s", resolved);
        } else {
            snprintf(gJBPath, sizeof gJBPath, "%s", jbroot);
        }
    }
}

// Rooted-JB prefixes mapped into the fixture jbroot, so detector probes of
// rooted-style paths (/usr/lib/libellekit.dylib, /Applications/Cydia.app,
// /etc/apt, ...) see the simulated jailbreak. The engine's own rootless
// gates never call access()/open() with these bare prefixes (they always
// use /var/jb + path), so the extra mapping cannot perturb the engine.
static const char* const kJBRootPrefixes[] = {
    "/usr/", "/bin/", "/sbin/", "/etc/", "/Applications/", "/Library/",
    "/private/", "/var/", "/jb",
};

// Maps into the CALLER's buffer (never a shared static): the shadow
// filter's engine call re-enters the wrapped functions (the engine's
// existence gates), and a shared buffer would be clobbered by the nested
// mapping — the outer wrap's real call would then run on the wrong path.
static const char* map_jb_into(const char* path, char* buf) {
    if(gJBPath[0] && path && path[0] == '/') {
        // "/var/jb" or "/var/jb/..." → gJBPath + suffix; "/var/jb2/x" stays put.
        if(strncmp(path, "/var/jb", 7) == 0 && (path[7] == '\0' || path[7] == '/')) {
            snprintf(buf, PATH_MAX, "%s%s", gJBPath, path + 7);
            return buf;
        }

        for(size_t i = 0; i < sizeof(kJBRootPrefixes) / sizeof(kJBRootPrefixes[0]); i++) {
            const char* prefix = kJBRootPrefixes[i];

            if(strncmp(path, prefix, strlen(prefix)) == 0) {
                snprintf(buf, PATH_MAX, "%s%s", gJBPath, path);
                return buf;
            }
        }
    }

    return path;
}

// -- shadow-active filter --------------------------------------------------
// When enabled, engine-restricted paths are hidden from the wrapped calls
// exactly like the device hook layer hides them (ENOENT for reads, EACCES
// for writes). The engine's own access()/realpath()/open() calls run with
// the in-filter guard set and pass through — the host analogue of
// SHADOW_INTERNAL_SCOPE.

static _Thread_local int gInFilter = 0;
static int gFilterEnabled = 0;

void shdw_shadow_filter_set_enabled(int enabled) {
    gFilterEnabled = enabled;
}

int shdw_shadow_filter(const char* path, int is_write); // ShadowFilter.m

static int filter_path(const char* path, int is_write) {
    if(gFilterEnabled && !gInFilter && path && path[0]) {
        int caller_errno = errno;
        gInFilter = 1;
        int blocked = shdw_shadow_filter(path, is_write);
        gInFilter = 0;
        // The engine may use libc while classifying a safe path. The wrapped
        // libc call below owns errno for its result, not that lookup.
        errno = caller_errno;
        return blocked;
    }

    return 0;
}

int __wrap_access(const char* path, int mode) {
    // Filter on the RAW path: the engine must decide on the real device
    // path. Filtering the mapped path would trip the restricted-root
    // fast-path for every fixture-backed file (the mapped path IS the
    // jbroot) — not device behavior.
    if(filter_path(path, 0)) {
        errno = ENOENT;
        return -1;
    }

    char mapped[PATH_MAX];
    return __real_access(map_jb_into(path, mapped), mode);
}

char* __wrap_realpath(const char* path, char* resolved) {
    if(filter_path(path, 0)) {
        errno = ENOENT;
        return NULL;
    }

    char mapped[PATH_MAX];
    return __real_realpath(map_jb_into(path, mapped), resolved);
}

int __wrap_open(const char* path, int flags, ...) {
    va_list ap;
    mode_t mode = 0;

    if(flags & O_CREAT) {
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    int is_write = (flags & (O_WRONLY | O_RDWR)) || (flags & O_CREAT);

    if(filter_path(path, is_write)) {
        errno = EACCES;
        return -1;
    }

    char mapped[PATH_MAX];
    return __real_open(map_jb_into(path, mapped), flags, mode);
}

// -- dyld symbol providers ------------------------------------------------
//
// _NSGetArgv: Core+Utilities.m's getExecutablePath uses the dyld private
// _NSGetArgv(), which neither libgnustep-base (unexported) nor libobjc2
// provides on Linux. The harness installs its own argv via
// shdw_fs_set_argv() (main()'s argv) before any engine use.

static char** gHarnessArgv = NULL;

void shdw_fs_set_argv(char** argv) {
    gHarnessArgv = argv;
}

char*** _NSGetArgv(void) {
    return &gHarnessArgv;
}

const char* dyld_image_path_containing_address(const void* addr) {
    (void) addr;
    return NULL;
}

// -- minimal dispatch_once ------------------------------------------------
// The framework sources call dispatch_once directly; on this stack there is
// no libdispatch. A global mutex is plenty: the harness is effectively
// single-threaded (no hooked hook threads), and correctness only requires
// run-once.
//
// The block runs with the in-filter guard raised: engine critical sections
// (e.g. isPathInRestrictedRoot's jbrootTarget computation, whose realpath
// is wrapped) must not be re-filtered — the filter's engine call would
// re-enter the same dispatch_once and self-deadlock on the mutex.

#include <pthread.h>

void dispatch_once(dispatch_once_t* predicate, void (^block)(void)) {
    if(__atomic_load_n(predicate, __ATOMIC_ACQUIRE) == 1) {
        return;
    }

    static pthread_mutex_t onceMutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&onceMutex);

    if(*predicate == 0) {
        gInFilter++;
        block();
        gInFilter--;
        __atomic_store_n(predicate, 1, __ATOMIC_RELEASE);
    }

    pthread_mutex_unlock(&onceMutex);
}

// -- minimal CFBundle API (see tests/hdr/CoreFoundation/CFBundle.h) -------

CFBundleRef CFBundleGetMainBundle(void) {
    return NULL;
}

CFStringRef CFBundleGetIdentifier(CFBundleRef bundle) {
    (void) bundle;
    return NULL;
}

#else // !__linux__

// Darwin: no interposition (real /var/jb handling is device semantics) and
// the real dyld provides the symbols. Keep the setter symbols so main.m
// compiles unchanged; the shadow filter is a no-op (the virtual FS it
// depends on is Linux-only).

void shdw_fs_set_jbroot(const char* jbroot) {
    (void) jbroot;
}

void shdw_fs_set_argv(char** argv) {
    (void) argv;
}

void shdw_shadow_filter_set_enabled(int enabled) {
    (void) enabled;
}

#endif
