#ifndef HOOKPROBE_IDENTITY_FIXTURE_H
#define HOOKPROBE_IDENTITY_FIXTURE_H

#include <stdint.h>

typedef struct {
    uint32_t version;
    int32_t stat_result;
    int32_t stat_errno;
    uint32_t dyld_image_count;
    int32_t objc_shadow_present;
    int32_t dyld_insert_present;
    int32_t bundle_proxy_present;
    int32_t scheme_result_count;
    uintptr_t caller_address;
} shdw_identity_fixture_result_t;

int shdw_identity_fixture_probe(const char* bundleID, const char* scheme,
                                shdw_identity_fixture_result_t* result);

#endif
