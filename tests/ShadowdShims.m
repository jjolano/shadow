// Host-side shims for the shadowd ledger battery.
//
// The ledger (shadowd/ledger.m) is Foundation-only and host-testable; these
// shims supply the three symbols it expects from the daemon:
//   - gIsRootless: the daemon sets it from access("/var/jb"); the battery
//     sets it per test (the virtual FS maps /var/jb in rootless mode).
//   - shdw_log: daemon logging — mirrored to stderr.
//   - sysctlbyname: glibc dropped it; the host has no kern.bootsessionuuid
//     anyway (the battery drives gBootUUID directly), so a failing stub is
//     the correct behavior.

#import <Foundation/Foundation.h>

#import <stdarg.h>
#import <stdio.h>
#import <errno.h>

bool gIsRootless = false;

void shdw_log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

int sysctlbyname(const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen) {
    (void) name;
    (void) oldp;
    (void) oldlenp;
    (void) newp;
    (void) newlen;
    errno = ENOENT;
    return -1;
}
