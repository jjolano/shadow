#ifndef hk_native_h
#define hk_native_h

// HookKit's own hooking engine: no ElleKit, Substrate or Substitute required.
//
// arm64/arm64e only. On armv7 every entry point degrades to "unsupported" --
// those devices always have Substrate, so no Thumb relocator is worth writing.
//
// Obtaining W^X is the load-bearing constraint. On A12+ the page tables are
// PPL-protected, so a dirty executable page needs relaxed codesigning. In a
// tweak-injected process that already holds: the injector had to relax it to
// load this dylib at all. Where it does not, every call fails cleanly.
//
// Not thread-safe against running code: the patch is not atomic, so hooks must
// be installed at load time, before other threads can enter the target. Same
// assumption ElleKit and Substrate make.

#include <stdbool.h>
#include <stddef.h>

// Internal to the framework: HookKit's only exported symbol is _HKSubstitutor
// (see HookKit.tbd), and these must not join the dynamic export table.
#ifndef HK_INTERNAL
#define HK_INTERNAL __attribute__((visibility("hidden")))
#endif

// Error codes reported by hk_native_last_error() alongside raw kern_return_t
// values (which are positive).
#define HK_NATIVE_ERR_UNSUPPORTED    (-1)
#define HK_NATIVE_ERR_SHORT_FUNCTION (-2)   // target too short to patch without clobbering its neighbour
#define HK_NATIVE_ERR_RELOCATE       (-3)   // prologue contains something unrelocatable
#define HK_NATIVE_ERR_NO_MEMORY      (-4)

// True when this build can hook at all (arm64/arm64e).
HK_INTERNAL bool hk_native_supported(void);

// Error from the most recent failing call. Process-wide, not per-thread: read
// it immediately after the call that failed.
HK_INTERNAL int hk_native_last_error(void);

// Side-effect-free capability preflight: exactly the checks the engine runs
// before writing (PAC strip, alignment, self-hook, short-function over the
// actual 4- or 16-byte branch window, with the final overwritten instruction
// excluded). Returns 0 when hk_native_hook_function would attempt the patch,
// otherwise an HK_NATIVE_ERR_* code. The engine's own hook path validates
// through this function, so a preflight accept and the hook can never
// disagree on the checks they share.
HK_INTERNAL int hk_native_preflight_function(void *target, void *replacement);

// Inline function hook. On success *out_orig receives a callable pointer to the
// original implementation (PAC-signed on arm64e).
HK_INTERNAL bool hk_native_hook_function(void *target, void *replacement, void **out_orig);

// Raw memory patch, no relocation. The region's original protection is restored
// afterwards, so this is safe on data as well as code.
HK_INTERNAL bool hk_native_patch_memory(void *target, const void *data, size_t size);

// Symbol lookup. Images must already be loaded -- an unloaded image has no
// runtime addresses to report.
typedef struct hk_image hk_image;

HK_INTERNAL hk_image *hk_native_open_image(const char *path);
HK_INTERNAL void hk_native_close_image(hk_image *image);
HK_INTERNAL void *hk_native_find_symbol(hk_image *image, const char *name);

#endif
