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
void litehook_rebind_symbol(const mach_header_u *targetHeader, void *replacee, void *replacement, bool (*exceptionFilter)(const mach_header_u *header));
