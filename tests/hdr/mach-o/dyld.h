// Minimal stub for Linux builds: dyld_priv.h references struct mach_header
// (by pointer only) via <mach-o/dyld.h>. The framework sources never call
// mach-o APIs on this platform (dyld_image_path_containing_address is
// stubbed in fsinterpose.c). macOS builds use the real header.
#ifndef _MACHO_DYLD_H_
#define _MACHO_DYLD_H_

struct mach_header;

#endif
