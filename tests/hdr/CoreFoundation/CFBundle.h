// Minimal CoreFoundation bundle API for Linux builds. Only the two functions
// Core+Utilities.m's getBundleIdentifier uses (which the harness never calls;
// the symbols must exist for linking, and a NULL bundle is the correct
// answer on a host). Implemented in fsinterpose.c. Force-included via
// -include tests/hdr/CoreFoundation/CFBundle.h in build-linux.sh only.
#ifndef CFBUNDLE_H
#define CFBUNDLE_H

typedef struct __CFBundle* CFBundleRef;
typedef struct __CFString* CFStringRef;

CFBundleRef CFBundleGetMainBundle(void);
CFStringRef CFBundleGetIdentifier(CFBundleRef bundle);

#endif
