#import "hooks.h"

// static kern_return_t (*original_vm_region)(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);
// static kern_return_t replaced_vm_region(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name) {
//     kern_return_t result = original_vm_region(target_task, address, size, flavor, info, infoCnt, object_name);

//     if(result == KERN_SUCCESS) {
//         // Hide executable flag
//         vm_region_basic_info_data_t* rinfo = (vm_region_basic_info_data_t *)info;
//         rinfo->protection &= ~VM_PROT_EXECUTE;
//     }

//     return result;
// }

static kern_return_t (*original_vm_region_64)(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);
static kern_return_t replaced_vm_region_64(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name) {
    kern_return_t result = original_vm_region_64(target_task, address, size, flavor, info, infoCnt, object_name);

    if(result == KERN_SUCCESS) {
        // Hide executable flag
        vm_region_basic_info_data_64_t* rinfo = (vm_region_basic_info_data_64_t *)info;
        rinfo->protection &= ~VM_PROT_EXECUTE;
    }

    return result;
}

// static kern_return_t (*original_vm_region_recurse)(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt);
// static kern_return_t replaced_vm_region_recurse(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt) {
//     kern_return_t result = original_vm_region_recurse(target_task, address, size, nesting_depth, info, infoCnt);

//     if(result == KERN_SUCCESS) {
//         // Hide executable flag
//         vm_region_basic_info_data_t* rinfo = (vm_region_basic_info_data_t *)info;
//         rinfo->protection &= ~VM_PROT_EXECUTE;
//     }

//     return result;
// }

static kern_return_t (*original_vm_region_recurse_64)(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt);
static kern_return_t replaced_vm_region_recurse_64(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt) {
    kern_return_t result = original_vm_region_recurse_64(target_task, address, size, nesting_depth, info, infoCnt);

    if(result == KERN_SUCCESS) {
        // Hide executable flag
        vm_region_basic_info_data_64_t* rinfo = (vm_region_basic_info_data_64_t *)info;
        rinfo->protection &= ~VM_PROT_EXECUTE;
    }

    return result;
}

void shadowhook_mem(void) {
    // MSHookFunction(vm_region, replaced_vm_region, (void **) &original_vm_region);
    MSHookFunction(vm_region_64, replaced_vm_region_64, (void **) &original_vm_region_64);
    // MSHookFunction(vm_region_recurse, replaced_vm_region_recurse, (void **) &original_vm_region_recurse);
    MSHookFunction(vm_region_recurse_64, replaced_vm_region_recurse_64, (void **) &original_vm_region_recurse_64);
}
