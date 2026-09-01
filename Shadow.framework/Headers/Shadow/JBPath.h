#ifndef shadow_jbpath_h
#define shadow_jbpath_h

#import <Foundation/Foundation.h>
#include <string.h>

// Jailbreak-root path seam. Three rootless conventions exist in the wild:
// - Rooted (unc0ver/checkra1n rootful): everything lives at the real root.
// - Legacy rootless (Dopamine/palera1n): fixed /var/jb bootstrap.
// - roothide: random-named `jbroot`, no /var/jb at all, resolved via
//   libroothide's jbroot() API.
//
// Theos bakes the install prefix into every build via
// THEOS_PACKAGE_INSTALL_PREFIX ("" rooted, "/var/jb" rootless; the roothide
// scheme defines SHADOW_ROOTHIDE and links libroothide).
//
// Runtime seam (non-roothide, non-harness): probe order
//   env JBROOT/SHADOW_JBROOT → realpath /var/jb → scan /private/preboot/*/jb → fallback compile-time prefix
// Keep JBIsRootless() runtime. Harness and roothide map as before via macros.

#ifdef SHADOW_ROOTHIDE
#import <roothide.h>
#define JBPath(p) jbroot(p)
#define JBIsRootless() YES
static inline BOOL shdw_is_restricted_root(const char *path) {
    if (!path || !path[0]) return NO;
    if (strcmp(path, "/private/preboot") == 0) return NO;
    if (strncmp(path, "/var/jb", 7) == 0 && (path[7] == '\0' || path[7] == '/')) return YES;
    if (strncmp(path, "/private/var/jb", 15) == 0 && (path[15] == '\0' || path[15] == '/')) return YES;
    if (strncmp(path, "/cores/", 7) == 0) return YES;
    if (strncmp(path, "/private/preboot", 16) == 0) return YES;
    NSString *root = jbroot(@"/");
    if (root) {
        const char *r = [root fileSystemRepresentation];
        size_t rl = strlen(r);
        if (rl > 0 && strncmp(path, r, rl) == 0) return YES;
    }
    return NO;
}
static inline BOOL shdw_is_restricted_root_c(const char *path) { return shdw_is_restricted_root(path); }
static inline BOOL shdw_path_contains_restricted_root_c(const char *path) {
    if (!path || !path[0]) return NO;
    if (strstr(path, "/var/jb") != NULL) return YES;
    if (strstr(path, "/private/preboot") != NULL) return YES;
    if (strstr(path, "/cores/") != NULL) return YES;
    NSString *root = jbroot(@"/");
    if (root) {
        const char *r = [root fileSystemRepresentation];
        if (r && r[0] && strstr(path, r) != NULL) return YES;
    }
    return NO;
}
static inline BOOL shdw_is_path_in_restricted_root(NSString *path) {
    return path ? shdw_is_restricted_root([path fileSystemRepresentation]) : NO;
}
static inline NSString* shdw_jbroot_prefix(void) {
    return jbroot(@"/");
}

#elif defined(SHADOW_TEST_HARNESS)
// Host test harness: no jailbreak, no theos prefix. The harness provides
// shdw_harness_set_jbpath(nil|fixture) (tests/ShdwPathShim.m) — nil = rooted
// pass-through, non-nil = rootless fixture mapping.
#import "ShdwPathShim.h"
#import <limits.h>
#import <unistd.h>
#define JBPath(p) shdw_harness_jbpath(p)
#define JBIsRootless() shdw_harness_rootless()
static inline BOOL shdw_is_restricted_root(const char *path) {
    if (!path || !path[0]) return NO;
    if (strcmp(path, "/private/preboot") == 0 || strcmp(path, "/preboot") == 0) return NO;
    if (strncmp(path, "/var/jb", 7) == 0 && (path[7] == '\0' || path[7] == '/')) return YES;
    if (strncmp(path, "/private/var/jb", 15) == 0 && (path[15] == '\0' || path[15] == '/')) return YES;
    if (strncmp(path, "/cores/", 7) == 0) return YES;
    if (strncmp(path, "/private/preboot", 16) == 0) return YES;
    if (strncmp(path, "/preboot", 8) == 0) return YES;
    // Harness: fixture jbroot via realpath("/var/jb") wrap
    char resolved[PATH_MAX];
    if (realpath("/var/jb", resolved)) {
        size_t rl = strlen(resolved);
        if (rl > 0 && strncmp(path, resolved, rl) == 0) return YES;
    }
    return NO;
}
static inline BOOL shdw_is_restricted_root_c(const char *path) { return shdw_is_restricted_root(path); }
static inline BOOL shdw_path_contains_restricted_root_c(const char *path) {
    if (!path || !path[0]) return NO;
    if (strstr(path, "/var/jb") != NULL) return YES;
    if (strstr(path, "/private/preboot") != NULL) return YES;
    if (strstr(path, "/preboot") != NULL) return YES;
    if (strstr(path, "/cores/") != NULL) return YES;
    char resolved[PATH_MAX];
    if (realpath("/var/jb", resolved)) {
        size_t rl = strlen(resolved);
        if (rl > 0 && strstr(path, resolved) != NULL) return YES;
    }
    return NO;
}
static inline BOOL shdw_is_path_in_restricted_root(NSString *path) {
    return path ? shdw_is_restricted_root([path fileSystemRepresentation]) : NO;
}
static inline NSString* shdw_jbroot_prefix(void) {
    char resolved[PATH_MAX];
    if (realpath("/var/jb", resolved)) return [NSString stringWithUTF8String:resolved];
    return shdw_harness_rootless() ? @"/var/jb" : @"";
}

#else
#ifndef THEOS_PACKAGE_INSTALL_PREFIX
#define THEOS_PACKAGE_INSTALL_PREFIX ""
#endif

__attribute__((visibility("default"))) NSString* _Nullable JBPath(NSString* _Nullable path);
__attribute__((visibility("default"))) BOOL JBIsRootless(void);

// Single-source restricted-root predicate (Core.m fast-path + RestrictionEngine).
__attribute__((visibility("default"))) BOOL shdw_is_restricted_root(const char* _Nullable path);
__attribute__((visibility("default"))) BOOL shdw_is_path_in_restricted_root(NSString* _Nullable path);
__attribute__((visibility("default"))) NSString* _Nonnull shdw_jbroot_prefix(void);
__attribute__((visibility("default"))) BOOL shdw_is_restricted_root_c(const char* _Nullable p);
__attribute__((visibility("default"))) BOOL shdw_path_contains_restricted_root_c(const char* _Nullable p);

#endif

#endif // shadow_jbpath_h
