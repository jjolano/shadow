#include "path_rewrite.h"

#include <string.h>

size_t shdw_path_munge_offset(const char *path) {
    size_t len = strlen(path);

    if(len == 0) {
        return (size_t)-1;
    }

    const char *last = strrchr(path, '/');
    size_t comp = last ? (size_t)(last - path) + 1 : 0;

    if(len - comp == 0) {
        return (size_t)-1;   // trailing slash — empty final component
    }

    // Middle of the final component: same-length rewrite, never the first
    // byte of the string (keeps the absolute/relative shape) and never the
    // last (keeps the NUL terminator at the same offset).
    return comp + (len - comp) / 2;
}

int shdw_path_munge_path(char *path) {
    size_t off = shdw_path_munge_offset(path);

    if(off == (size_t)-1) {
        return 0;
    }

    path[off] = 0x01;
    return 1;
}

#if defined(__APPLE__)

#include <mach/mach.h>

int shdw_path_buf_writable(const char *ptr) {
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    vm_address_t region = (vm_address_t)ptr;
    vm_size_t region_size = 0;
    mach_port_t object_name = MACH_PORT_NULL;

    if(vm_region_64(mach_task_self(), &region, &region_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_count, &object_name) != KERN_SUCCESS) {
        return 0;
    }

    return (info.protection & VM_PROT_WRITE) != 0;
}

#endif  // __APPLE__