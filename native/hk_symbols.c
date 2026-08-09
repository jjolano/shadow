#include "hk_native.h"

#if defined(__arm64__) || defined(__aarch64__)

#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct hk_image {
    void *map;                      // owned mmap of an on-disk Mach-O, or NULL for cache images
    size_t map_size;
    intptr_t slide;
    const struct nlist_64 *nlist;
    uint32_t nlist_count;
    const char *strings;
    uint32_t strings_size;
    void *dl_handle;                // fallback for exported symbols
};

#pragma mark - Loaded image lookup

static bool find_loaded_image(const char *path, const struct mach_header_64 **out_header, intptr_t *out_slide) {
    uint32_t count = _dyld_image_count();

    for(uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);

        if(name && strcmp(name, path) == 0) {
            *out_header = (const struct mach_header_64 *)_dyld_get_image_header(i);
            *out_slide = _dyld_get_image_vmaddr_slide(i);
            return true;
        }
    }

    // Second pass through symlinks. Shared cache images have no file on disk,
    // so realpath fails for them -- they can only match the pass above.
    char resolved[PATH_MAX];

    if(!realpath(path, resolved)) {
        return false;
    }

    for(uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        char other[PATH_MAX];

        if(name && realpath(name, other) && strcmp(other, resolved) == 0) {
            *out_header = (const struct mach_header_64 *)_dyld_get_image_header(i);
            *out_slide = _dyld_get_image_vmaddr_slide(i);
            return true;
        }
    }

    return false;
}

#pragma mark - dyld shared cache local symbols

// Cached images keep their local symbols in the cache files but outside the
// mapped regions, so they have to be read from disk. iOS 16+ splits them into a
// .symbols subcache; iOS 15 and earlier embed them in the main cache. Both use
// the same header layout, so one probe loop covers both.

extern const void *_dyld_get_shared_cache_range(size_t *length) __attribute__((weak_import));

// Byte offsets into dyld_cache_header. Fixed since the format was introduced;
// the header only ever grew past them.
#define HK_DCH_MAGIC              0
#define HK_DCH_MAPPING_OFFSET     16
#define HK_DCH_LOCAL_SYMS_OFFSET  72
#define HK_DCH_LOCAL_SYMS_SIZE    80
#define HK_DCH_MIN_MAPPING_OFFSET 88    // header must reach at least this far for the fields above to exist

struct hk_local_symbols_info {
    uint32_t nlistOffset;
    uint32_t nlistCount;
    uint32_t stringsOffset;
    uint32_t stringsSize;
    uint32_t entriesOffset;
    uint32_t entriesCount;
};

struct hk_cache_symbols {
    const uint8_t *map;
    size_t map_size;
    const struct nlist_64 *nlist;
    uint32_t nlist_count;
    const char *strings;
    uint32_t strings_size;
    const uint8_t *entries;
    uint32_t entries_count;
    size_t entry_stride;            // 12 (uint32 dylibOffset) or 16 (uint64)
    bool valid;
};

static uint64_t entry_dylib_offset(const uint8_t *entry, size_t stride) {
    if(stride == 16) {
        uint64_t value;
        memcpy(&value, entry, sizeof(value));
        return value;
    }

    uint32_t value;
    memcpy(&value, entry, sizeof(value));
    return value;
}

static uint32_t entry_nlist_start(const uint8_t *entry, size_t stride) {
    uint32_t value;
    memcpy(&value, entry + (stride == 16 ? 8 : 4), sizeof(value));
    return value;
}

static uint32_t entry_nlist_count(const uint8_t *entry, size_t stride) {
    uint32_t value;
    memcpy(&value, entry + (stride == 16 ? 12 : 8), sizeof(value));
    return value;
}

// Discriminates the 32-bit and 64-bit entry layouts: with the wrong stride the
// nlist ranges read as garbage and overrun the symbol table almost immediately.
static bool entries_plausible(const uint8_t *entries, uint32_t count, size_t stride,
                              uint32_t nlist_total, size_t available) {
    if(count == 0 || (size_t)count * stride > available) {
        return false;
    }

    uint32_t probe = count < 8 ? count : 8;

    for(uint32_t i = 0; i < probe; i++) {
        const uint8_t *entry = entries + ((size_t)i * stride);

        if((uint64_t)entry_nlist_start(entry, stride) + entry_nlist_count(entry, stride) > nlist_total) {
            return false;
        }
    }

    return true;
}

static bool parse_cache_symbols(const uint8_t *map, size_t map_size, struct hk_cache_symbols *out) {
    if(map_size < 0x100 || memcmp(map + HK_DCH_MAGIC, "dyld_v1", 7) != 0) {
        return false;
    }

    uint32_t mapping_offset;
    memcpy(&mapping_offset, map + HK_DCH_MAPPING_OFFSET, sizeof(mapping_offset));

    if(mapping_offset < HK_DCH_MIN_MAPPING_OFFSET) {
        return false;
    }

    uint64_t syms_offset;
    uint64_t syms_size;
    memcpy(&syms_offset, map + HK_DCH_LOCAL_SYMS_OFFSET, sizeof(syms_offset));
    memcpy(&syms_size, map + HK_DCH_LOCAL_SYMS_SIZE, sizeof(syms_size));

    if(syms_offset == 0 || syms_size < sizeof(struct hk_local_symbols_info)) {
        return false;
    }

    if(syms_offset > map_size || syms_size > map_size - syms_offset) {
        return false;
    }

    const uint8_t *region = map + syms_offset;
    struct hk_local_symbols_info info;
    memcpy(&info, region, sizeof(info));

    // Every sub-range must sit inside the local symbols region.
    if((uint64_t)info.nlistOffset + ((uint64_t)info.nlistCount * sizeof(struct nlist_64)) > syms_size) {
        return false;
    }

    if((uint64_t)info.stringsOffset + info.stringsSize > syms_size) {
        return false;
    }

    if(info.entriesOffset > syms_size) {
        return false;
    }

    const uint8_t *entries = region + info.entriesOffset;
    size_t entries_available = (size_t)(syms_size - info.entriesOffset);
    size_t stride = 0;

    // A separate .symbols subcache implies the 64-bit layout, but probe rather
    // than assume: validate one and fall back to the other.
    if(entries_plausible(entries, info.entriesCount, 16, info.nlistCount, entries_available)) {
        stride = 16;
    } else if(entries_plausible(entries, info.entriesCount, 12, info.nlistCount, entries_available)) {
        stride = 12;
    } else {
        return false;
    }

    out->map = map;
    out->map_size = map_size;
    out->nlist = (const struct nlist_64 *)(region + info.nlistOffset);
    out->nlist_count = info.nlistCount;
    out->strings = (const char *)(region + info.stringsOffset);
    out->strings_size = info.stringsSize;
    out->entries = entries;
    out->entries_count = info.entriesCount;
    out->entry_stride = stride;
    out->valid = true;
    return true;
}

// Mapped once for the process lifetime: the region is large and read-only, and
// every cached image needs it.
static const struct hk_cache_symbols *cache_symbols(void) {
    static struct hk_cache_symbols symbols;
    static dispatch_once_t once = 0;

    dispatch_once(&once, ^{
        // Deliberately NOT routed through HKJBPath. That prefixes the
        // jailbreak root (/var/jb/...) onto paths a rootless install
        // relocates, and the shared cache is not one of them -- it stays at
        // its system path on every jailbreak. Prefixing here would only ever
        // produce paths that do not exist.
        static const char *candidates[] = {
            "/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e.symbols",
            "/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64.symbols",
            "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
            "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
        };

        for(size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
            int fd = open(candidates[i], O_RDONLY);

            if(fd < 0) {
                continue;
            }

            struct stat st;

            if(fstat(fd, &st) != 0 || st.st_size <= 0) {
                close(fd);
                continue;
            }

            void *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            close(fd);

            if(map == MAP_FAILED) {
                continue;
            }

            if(parse_cache_symbols((const uint8_t *)map, (size_t)st.st_size, &symbols)) {
                return;
            }

            munmap(map, (size_t)st.st_size);
        }
    });

    return symbols.valid ? &symbols : NULL;
}

// A cached dylib's mach_header and the cache base are both slid by the same
// amount, so their difference is exactly the unslid file offset the local
// symbols entries are keyed by.
static bool cache_image_offset(const void *header, uint64_t *out_offset) {
    if(!_dyld_get_shared_cache_range) {
        return false;
    }

    size_t length = 0;
    const void *base = _dyld_get_shared_cache_range(&length);

    if(!base || length == 0) {
        return false;
    }

    uintptr_t addr = (uintptr_t)header;
    uintptr_t start = (uintptr_t)base;

    if(addr < start || addr >= start + length) {
        return false;
    }

    *out_offset = (uint64_t)(addr - start);
    return true;
}

static bool bind_cache_symbols(const void *header, struct hk_image *image) {
    const struct hk_cache_symbols *symbols = cache_symbols();
    uint64_t dylib_offset = 0;

    if(!symbols || !cache_image_offset(header, &dylib_offset)) {
        return false;
    }

    for(uint32_t i = 0; i < symbols->entries_count; i++) {
        const uint8_t *entry = symbols->entries + ((size_t)i * symbols->entry_stride);

        if(entry_dylib_offset(entry, symbols->entry_stride) != dylib_offset) {
            continue;
        }

        image->nlist = symbols->nlist + entry_nlist_start(entry, symbols->entry_stride);
        image->nlist_count = entry_nlist_count(entry, symbols->entry_stride);
        image->strings = symbols->strings;
        image->strings_size = symbols->strings_size;
        return true;
    }

    return false;
}

#pragma mark - On-disk Mach-O symbol table

static bool bind_ondisk_symbols(const char *path, struct hk_image *image) {
    int fd = open(path, O_RDONLY);

    if(fd < 0) {
        return false;
    }

    struct stat st;

    if(fstat(fd, &st) != 0 || (size_t)st.st_size < sizeof(struct mach_header_64)) {
        close(fd);
        return false;
    }

    size_t size = (size_t)st.st_size;
    void *map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if(map == MAP_FAILED) {
        return false;
    }

    const struct mach_header_64 *mh = (const struct mach_header_64 *)map;

    // Thin arm64 images only. iOS ships thin binaries; a fat header here means
    // we simply fall through to dlsym.
    if(mh->magic != MH_MAGIC_64) {
        munmap(map, size);
        return false;
    }

    const uint8_t *cursor = (const uint8_t *)map + sizeof(struct mach_header_64);
    const uint8_t *limit = (const uint8_t *)map + size;

    if((uint64_t)sizeof(struct mach_header_64) + mh->sizeofcmds > size) {
        munmap(map, size);
        return false;
    }

    for(uint32_t i = 0; i < mh->ncmds; i++) {
        if(cursor + sizeof(struct load_command) > limit) {
            break;
        }

        const struct load_command *lc = (const struct load_command *)cursor;

        if(lc->cmdsize < sizeof(struct load_command) || cursor + lc->cmdsize > limit) {
            break;
        }

        if(lc->cmd == LC_SYMTAB && lc->cmdsize >= sizeof(struct symtab_command)) {
            const struct symtab_command *symtab = (const struct symtab_command *)lc;
            uint64_t symend = (uint64_t)symtab->symoff + ((uint64_t)symtab->nsyms * sizeof(struct nlist_64));
            uint64_t strend = (uint64_t)symtab->stroff + symtab->strsize;

            if(symtab->nsyms == 0 || symend > size || strend > size) {
                break;
            }

            image->map = map;
            image->map_size = size;
            image->nlist = (const struct nlist_64 *)((const uint8_t *)map + symtab->symoff);
            image->nlist_count = symtab->nsyms;
            image->strings = (const char *)map + symtab->stroff;
            image->strings_size = symtab->strsize;
            return true;
        }

        cursor += lc->cmdsize;
    }

    munmap(map, size);
    return false;
}

#pragma mark - Public API

hk_image *hk_native_open_image(const char *path) {
    if(!path || !*path) {
        return NULL;
    }

    const struct mach_header_64 *header = NULL;
    intptr_t slide = 0;

    // Without a loaded image there is no slide, and therefore no runtime
    // address any symbol could resolve to.
    if(!find_loaded_image(path, &header, &slide)) {
        return NULL;
    }

    struct hk_image *image = calloc(1, sizeof(struct hk_image));

    if(!image) {
        return NULL;
    }

    image->slide = slide;
    image->dl_handle = dlopen(path, RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD);

    if(!bind_cache_symbols(header, image)) {
        bind_ondisk_symbols(path, image);
    }

    // Even with no symbol table the handle is useful: dlsym still resolves
    // exported symbols.
    return (hk_image *)image;
}

void hk_native_close_image(hk_image *image) {
    if(!image) {
        return;
    }

    if(image->map) {
        munmap(image->map, image->map_size);
    }

    if(image->dl_handle) {
        dlclose(image->dl_handle);
    }

    free(image);
}

// Substrate-style names arrive without the leading underscore that Mach-O
// symbol tables carry ("malloc"); C++ mangled names keep theirs.
static bool symbol_matches(const char *entry, const char *name) {
    if(strcmp(entry, name) == 0) {
        return true;
    }

    return entry[0] == '_' && strcmp(entry + 1, name) == 0;
}

void *hk_native_find_symbol(hk_image *image, const char *name) {
    if(!image || !name || !*name) {
        return NULL;
    }

    if(image->nlist && image->strings) {
        for(uint32_t i = 0; i < image->nlist_count; i++) {
            const struct nlist_64 *symbol = &image->nlist[i];

            if(symbol->n_un.n_strx == 0 || symbol->n_un.n_strx >= image->strings_size) {
                continue;
            }

            if((symbol->n_type & N_TYPE) != N_SECT || symbol->n_value == 0) {
                continue;
            }

            if(symbol_matches(image->strings + symbol->n_un.n_strx, name)) {
                return (void *)(uintptr_t)((intptr_t)symbol->n_value + image->slide);
            }
        }
    }

    if(image->dl_handle) {
        return dlsym(image->dl_handle, name);
    }

    return NULL;
}

#else   // !arm64

hk_image *hk_native_open_image(const char *path) {
    (void)path;
    return NULL;
}

void hk_native_close_image(hk_image *image) {
    (void)image;
}

void *hk_native_find_symbol(hk_image *image, const char *name) {
    (void)image; (void)name;
    return NULL;
}

#endif
