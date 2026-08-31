#ifndef shadow_filters_h
#define shadow_filters_h

#include <stdint.h>
#include <string.h>

#ifndef MNT_RDONLY
#define MNT_RDONLY 0x00000001
#endif

// Returns 1 to keep the mount record, 0 to remove it. `restricted` is the
// caller's isCPathRestricted verdict on f_mntonname/f_mntfromname. When
// kept, statfsFlags && mntonname == "/" ORs MNT_RDONLY into *flags.
static inline int shdw_mount_filter(const char* mntonname, const char* mntfromname, uint32_t* flags, int statfsFlags, int restricted) {
    (void) mntfromname;
    if(restricted) return 0;
    if(statfsFlags && mntonname && strcmp(mntonname, "/") == 0 && flags) {
        *flags |= MNT_RDONLY;
    }
    return 1;
}

// 1 = jailbreak snapshot name (hide), 0 = keep. Exact-match deny-list.
static inline int shdw_snapshot_is_jb(const char* name) {
    static const char* const jb_snapshots[] = { "fakefs", NULL };
    if(!name) return 0;
    for(int i = 0; jb_snapshots[i]; i++) {
        if(strcmp(name, jb_snapshots[i]) == 0) return 1;
    }
    return 0;
}

#endif