#import "hooks.h"

// vm_region policy: a returned region whose start address lies inside a
// restricted image interval is SKIPPED — the original is re-called to
// advance to the next region — instead of having its protection bits
// rewritten. Mutating VM_PROT_EXECUTE (the old blanket-NX) contradicts the
// region's max_protection and fingerprints the hook; skipping restricted
// intervals removes the mapping enumeration leak while leaving every other
// region byte-identical to stock. Regions that cannot be classified pass
// through UNCHANGED (protection is never mutated).
static kern_return_t (*original_vm_region_64)(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);
static kern_return_t replaced_vm_region_64(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name) {
    for(;;) {
        kern_return_t result = original_vm_region_64(target_task, address, size, flavor, info, infoCnt, object_name);

        if(result != KERN_SUCCESS) {
            return result;
        }

        if(!isCallerExternal() || flavor == VM_REGION_TOP_INFO || ![_shadow isAddrRestricted:(void *) *address]) {
            return result;
        }

        // Restricted region: drop the object-name send right this skipped
        // call returned (it is ours to deallocate) and advance to the next
        // region. Each successful original call already advanced *address
        // past the region it returned, so the loop resumes where the kernel
        // left off and terminates at the end of the map (the next call then
        // returns an error).
        if(object_name && *object_name != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), *object_name);
            *object_name = MACH_PORT_NULL;
        }
    }
}

static kern_return_t (*original_vm_region_recurse_64)(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt);
static kern_return_t replaced_vm_region_recurse_64(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt) {
    for(;;) {
        kern_return_t result = original_vm_region_recurse_64(target_task, address, size, nesting_depth, info, infoCnt);

        if(result != KERN_SUCCESS) {
            return result;
        }

        if(!isCallerExternal() || ![_shadow isAddrRestricted:(void *) *address]) {
            return result;
        }
    }
}

// mach_vm_region/mach_vm_region_recurse: the mach_vm_* twins of the two
// hooks above — same enumeration semantics over 64-bit address/size types,
// same skip policy (a returned region inside a restricted interval is
// SKIPPED and the original re-called to advance). The SDK's mach_vm.h is a
// stub, so the prototypes are declared here; mach_vm_region takes the
// flavor as an in/out pointer (unlike the vm_* variant's by-value flavor),
// hence the dereference in the TOP_INFO pass-through.
extern kern_return_t mach_vm_region(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, vm_region_flavor_t* flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);
static kern_return_t (*original_mach_vm_region)(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, vm_region_flavor_t* flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);
static kern_return_t replaced_mach_vm_region(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, vm_region_flavor_t* flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name) {
    for(;;) {
        kern_return_t result = original_mach_vm_region(target_task, address, size, flavor, info, infoCnt, object_name);

        if(result != KERN_SUCCESS) {
            return result;
        }

        if(!isCallerExternal() || (flavor && *flavor == VM_REGION_TOP_INFO) || ![_shadow isAddrRestricted:(void *) *address]) {
            return result;
        }

        // Restricted region: drop the object-name send right this skipped
        // call returned (it is ours to deallocate) and advance to the next
        // region — same loop discipline as the vm_region_64 hook above.
        if(object_name && *object_name != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), *object_name);
            *object_name = MACH_PORT_NULL;
        }
    }
}

extern kern_return_t mach_vm_region_recurse(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt);
static kern_return_t (*original_mach_vm_region_recurse)(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt);
static kern_return_t replaced_mach_vm_region_recurse(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt) {
    for(;;) {
        kern_return_t result = original_mach_vm_region_recurse(target_task, address, size, nesting_depth, info, infoCnt);

        if(result != KERN_SUCCESS) {
            return result;
        }

        if(!isCallerExternal() || ![_shadow isAddrRestricted:(void *) *address]) {
            return result;
        }
    }
}

void shadowhook_mem(HKSubstitutor* hooks) {
    [hooks hookFunction:vm_region_64 withReplacement:replaced_vm_region_64 outOldPtr:(void **) &original_vm_region_64];
    [hooks hookFunction:vm_region_recurse_64 withReplacement:replaced_vm_region_recurse_64 outOldPtr:(void **) &original_vm_region_recurse_64];
    [hooks hookFunction:mach_vm_region withReplacement:replaced_mach_vm_region outOldPtr:(void **) &original_mach_vm_region];
    [hooks hookFunction:mach_vm_region_recurse withReplacement:replaced_mach_vm_region_recurse outOldPtr:(void **) &original_mach_vm_region_recurse];
}
