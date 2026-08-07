// Minimal dispatch_once for Linux builds. gnustep-base on this stack has no
// libdispatch, and the Shadow framework sources call dispatch_once directly
// (on iOS/macOS it comes transitively from Foundation). The implementation
// lives in fsinterpose.c. This header is force-included via
// -include tests/hdr/dispatch/once.h in build-linux.sh only.
#ifndef DISPATCH_ONCE_H
#define DISPATCH_ONCE_H

#include <stddef.h>

typedef long dispatch_once_t;

void dispatch_once(dispatch_once_t* predicate, void (^block)(void));

#endif
