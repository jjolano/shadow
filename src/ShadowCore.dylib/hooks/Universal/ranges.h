#ifndef shadow_hooks_ranges_h
#define shadow_hooks_ranges_h

// Image address-range tables, and the pure lookup over them.
//
// Split out of hooks.h so the host test harness can exercise the lookup:
// hooks.h pulls UIKit, mach and sandbox headers and only builds for iOS, while
// everything here is plain C over <stdint.h>. hooks.h wraps this with the
// atomics, the dyld walk that fills the tables, and the -[Shadow
// isAddrRestricted:] fallback.

#include <stdint.h>
#include <string.h>

// Caller truth is deliberately narrower than the image-hiding policy. Only
// the binaries shipped by this package, at literal package paths, may
// contribute an internal caller range. Aliases, symlinks, basenames, prefixes,
// case variants, and dependency frameworks are external callers unless they
// enter an explicit SHADOW_INTERNAL_SCOPE.
static inline int shdw_is_canonical_shadow_runtime_path(const char* path) {
    static const char* const paths[] = {
        "/Library/MobileSubstrate/DynamicLibraries/Shadow.dylib",
        "/var/jb/Library/MobileSubstrate/DynamicLibraries/Shadow.dylib",
        "/Library/Frameworks/Shadow.framework/Shadow",
        "/var/jb/Library/Frameworks/Shadow.framework/Shadow",
        "/usr/lib/ShadowCore.dylib",
        "/var/jb/usr/lib/ShadowCore.dylib",
        NULL,
    };

    if(!path || !path[0]) {
        return 0;
    }

    for(unsigned int i = 0; paths[i]; i++) {
        if(strcmp(path, paths[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

// dyld reports rootless images through /var/jb's resolved physical root, not
// necessarily through the /var/jb alias. Keep that form exact as well: the
// caller supplies the one runtime-resolved root, and only package suffixes
// listed here are trusted.
static inline int shdw_is_canonical_shadow_runtime_path_under_root(const char* path, const char* root) {
    static const char* const suffixes[] = {
        "/Library/MobileSubstrate/DynamicLibraries/Shadow.dylib",
        "/Library/Frameworks/Shadow.framework/Shadow",
        "/usr/lib/ShadowCore.dylib",
        NULL,
    };

    if(!path || !path[0] || !root || !root[0]) {
        return 0;
    }

    size_t rootLength = strlen(root);

    while(rootLength > 1 && root[rootLength - 1] == '/') {
        rootLength -= 1;
    }

    for(unsigned int i = 0; suffixes[i]; i++) {
        size_t suffixLength = strlen(suffixes[i]);

        if(strlen(path) == rootLength + suffixLength &&
           strncmp(path, root, rootLength) == 0 &&
           strcmp(path + rootLength, suffixes[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

typedef struct {
    uintptr_t base, end;
} shdw_range_t;

#define SHADOW_OWN_IMAGE_MAX 16

typedef struct {
    uint32_t count;
    shdw_range_t range[SHADOW_OWN_IMAGE_MAX];
} shdw_own_ranges_t;

#define SHADOW_RESTRICTED_IMAGE_MAX 64

typedef struct {
    uint32_t count;
    // Set when the walk found more restricted images than the table holds.
    // A missing range reads as "not restricted", and under-reporting is the
    // unsafe direction, so a truncated table must not be answered from.
    unsigned char overflowed;
    // Ruleset generation the table was classified under. A reload can change
    // an already-loaded image's verdict without any image event, so entries
    // stamped with an older generation are no longer trustworthy.
    uint64_t generation;
    shdw_range_t range[SHADOW_RESTRICTED_IMAGE_MAX];
} shdw_restricted_ranges_t;

typedef enum {
    SHDW_RANGE_NO = 0,       // inside no restricted image
    SHDW_RANGE_YES = 1,      // inside a restricted image
    SHDW_RANGE_UNKNOWN = 2   // table cannot answer; ask the real predicate
} shdw_range_verdict_t;

// Is `addr` inside a restricted image, according to `table`?
//
// UNKNOWN whenever the table cannot answer completely — it overflowed, or it
// was classified under an older ruleset generation than `generation`. Both are
// rare and both must route to -[Shadow isAddrRestricted:] rather than guess.
//
// A NULL address, and an address inside none of the ranges, are both NO: that
// matches -[Shadow isAddrRestricted:], which answers NO for an address in no
// image (dyld_image_path_containing_address returns NULL there).
static inline shdw_range_verdict_t shdw_ranges_lookup(const shdw_restricted_ranges_t* table, uint64_t generation, uintptr_t addr) {
    if(!table) {
        return SHDW_RANGE_UNKNOWN;
    }

    if(!addr) {
        return SHDW_RANGE_NO;
    }

    if(table->overflowed || table->generation != generation) {
        return SHDW_RANGE_UNKNOWN;
    }

    for(uint32_t i = 0; i < table->count; i++) {
        if(addr >= table->range[i].base && addr < table->range[i].end) {
            return SHDW_RANGE_YES;
        }
    }

    return SHDW_RANGE_NO;
}

#endif
