// Host shim for Linux builds: glibc >= 2.32 removed sys/sysctl.h. macOS
// builds use the real header (the Darwin Makefile branch does not include
// this directory).
#ifndef SYS_SYSCTL_H
#define SYS_SYSCTL_H

#include <stddef.h>

int sysctlbyname(const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen);

#endif
