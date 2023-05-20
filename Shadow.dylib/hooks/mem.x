#import "hooks.h"

static kern_return_t (*original_vm_region_64)(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);
static kern_return_t replaced_vm_region_64(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name) {
    kern_return_t result = original_vm_region_64(target_task, address, size, flavor, info, infoCnt, object_name);

    if(!isCallerTweak() && result == KERN_SUCCESS && flavor != VM_REGION_TOP_INFO) {
        // Hide executable flag
        vm_region_basic_info_64_t rinfo = (vm_region_basic_info_64_t)info;

        if(rinfo->protection) {
            rinfo->protection |= VM_PROT_READ;
            rinfo->protection &= ~VM_PROT_EXECUTE;
        }
    }

    return result;
}

static kern_return_t (*original_vm_region_recurse_64)(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt);
static kern_return_t replaced_vm_region_recurse_64(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt) {
    kern_return_t result = original_vm_region_recurse_64(target_task, address, size, nesting_depth, info, infoCnt);

    if(!isCallerTweak() && result == KERN_SUCCESS) {
        // Hide executable flag
        vm_region_basic_info_64_t rinfo = (vm_region_basic_info_64_t)info;

        if(rinfo->protection) {
            rinfo->protection |= VM_PROT_READ;
            rinfo->protection &= ~VM_PROT_EXECUTE;
        }
    }

    return result;
}

void shadowhook_mem(HKSubstitutor* hooks) {
    MSHookFunction(vm_region_64, replaced_vm_region_64, (void **) &original_vm_region_64);
    MSHookFunction(vm_region_recurse_64, replaced_vm_region_recurse_64, (void **) &original_vm_region_recurse_64);
}
