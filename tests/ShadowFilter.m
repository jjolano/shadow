// Shadow-active filter bridge (Linux harness).
//
// Consulted by the fsinterpose wrappers: when the filter is enabled, every
// access()/open()/realpath() call on a path Shadow's engine deems
// restricted is answered ENOENT (reads) or EACCES (writes) — exactly what
// the device hook layer does. The engine's own internal access()/realpath()
// calls are protected from recursion by the interposer's thread-local
// in-filter guard (see fsinterpose.c), mirroring SHADOW_INTERNAL_SCOPE.

#import <Foundation/Foundation.h>
#import <Shadow.h>
#import "fsinterpose.h"

int shdw_shadow_filter(const char* path, int is_write) {
    if(!path || !path[0]) {
        return 0;
    }

    NSString* p = [NSString stringWithUTF8String:path];
    NSDictionary* options = is_write
        ? @{kShadowRestrictionOperation : kShadowRestrictionOpWrite}
        : nil;

    return [[Shadow sharedInstance] isPathRestricted:p options:options] ? 1 : 0;
}
