#include <stdio.h>
#include <stdbool.h>
#include <mach/mach.h>
#include <mach-o/loader.h>

#ifdef __arm64__
typedef struct mach_header_64 mach_header_u;
typedef struct segment_command_64 segment_command_u;
typedef struct section_64 section_u;
typedef struct nlist_64 nlist_u;
#define LC_SEGMENT_U LC_SEGMENT_64
#else
typedef struct mach_header mach_header_u;
typedef struct segment_command segment_command_u;
typedef struct section section_u;
typedef struct nlist nlist_u;
#define LC_SEGMENT_U LC_SEGMENT
#endif

extern kern_return_t (*litehook_hook_memory)(void *target, void *source, size_t sourceSize);

const char *litehook_locate_dsc(void);

void *litehook_find_symbol(const mach_header_u *header, const char *symbolName);
void *litehook_find_dsc_symbol(const char *imagePath, const char *symbolName);
kern_return_t litehook_hook_function(void *source, void *target);

#define LITEHOOK_REBIND_GLOBAL NULL
// Rebind `replacee` to `replacement` in the given image (or every loaded
// image, past and future, when targetHeader is LITEHOOK_REBIND_GLOBAL).
// Returns KERN_SUCCESS on success; KERN_MEMORY_FAILURE when growing the global
// rebind list fails (the live list is left untouched), KERN_FAILURE when the
// replacement's image cannot be located, KERN_INVALID_ARGUMENT on bad args.
//
// When non-NULL, *outMatchCount receives the number of GOT/import slots this
// call actually rewrote — captured under the same lock as the apply, so the
// caller's zero-match decision cannot race a concurrent dyld add-image walk.
// It is also written (to 0) on the failure paths above.
kern_return_t litehook_rebind_symbol(const mach_header_u *targetHeader, void *replacee, void *replacement, bool (*exceptionFilter)(const mach_header_u *header), unsigned int *outMatchCount);
