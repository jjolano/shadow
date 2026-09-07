// Record handling only; snapshot policy wiring is checked by verify-mount-query.py.
#include <assert.h>
#include <stdio.h>
#include "../src/ShadowCore.dylib/hooks/Universal/filters.h"

int main(void) {
    uint32_t flags = 0x40;
    assert(!shdw_mount_filter("/custom-volume", "/custom-source", &flags, 1, 1));
    assert(flags == 0x40);
    assert(shdw_mount_filter("/custom-volume", "/custom-source", &flags, 1, 0));
    assert(flags == 0x40);

    // A ruleset verdict, not a second hardcoded path policy, controls removal.
    assert(shdw_mount_filter("/Library/Frameworks", "/dev/disk1", &flags, 1, 0));
    assert(!shdw_mount_filter("/", "/custom-source", &flags, 1, 1));
    assert(flags == 0x40);
    assert(shdw_mount_filter("/", "/dev/disk1", &flags, 1, 0));
    assert(flags == (0x40 | MNT_RDONLY));

    flags = 0x40;
    assert(shdw_mount_filter("/", "/dev/disk1", &flags, 0, 0));
    assert(flags == 0x40);
    assert(shdw_mount_filter(NULL, NULL, NULL, 1, 0));
    puts("verify-mount-filter: all assertions passed");
    return 0;
}
