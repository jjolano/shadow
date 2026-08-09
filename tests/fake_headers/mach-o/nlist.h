// Host-test stub for Apple's <mach-o/nlist.h>. The vendored libsubstitute
// header needs `struct nlist_64` (for substitute_sym under __APPLE__); the
// classifier under test never touches it. Minimal definitions only.
#ifndef fake_mach_o_nlist_h
#define fake_mach_o_nlist_h
struct nlist_64 {
    uint64_t n_un;
    uint8_t n_type;
    uint8_t n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};
#endif
