#import "UniversalHooks.h"

// Anti-fishhook writes use this copy-on-write protection before replacing a
// lazy/non-lazy import slot. Refuse it only when the requested range actually
// overlaps a slot Shadow rebound; ordinary vm_protect/fishhook users keep
// native behavior.
static BOOL shdw_is_import_slot_rewrite(task_t task, vm_address_t address,
                                        vm_size_t size, boolean_t setMaximum,
                                        vm_prot_t protection) {
    return task == mach_task_self() && !setMaximum &&
        protection == (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) &&
        SHDWRangeOverlapsProtectedImportSlots((uintptr_t)address, (size_t)size);
}

static kern_return_t (*original_vm_protect_imports)(vm_map_t, vm_address_t,
                                                     vm_size_t, boolean_t,
                                                     vm_prot_t);
static kern_return_t replaced_vm_protect_imports(vm_map_t task,
                                                  vm_address_t address,
                                                  vm_size_t size,
                                                  boolean_t setMaximum,
                                                  vm_prot_t protection) {
    if(isCallerExternal() &&
       shdw_is_import_slot_rewrite(task, address, size, setMaximum, protection)) {
        return KERN_PROTECTION_FAILURE;
    }

    return original_vm_protect_imports(task, address, size, setMaximum, protection);
}

void shdw_universal_import_slot_protection(SHDWHookSession* hooks) {
    // Resolve the export itself, not this image's import stub: that stub is
    // exactly what the rebinder replaces and would recurse after installation.
    if(!original_vm_protect_imports) {
        original_vm_protect_imports = (kern_return_t (*)(
            vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t
        ))dlsym(RTLD_DEFAULT, "vm_protect");
    }
    if(!original_vm_protect_imports) return;

    [hooks hookRebindSymbol:@"vm_protect"
            withReplacement:replaced_vm_protect_imports
                   outOldPtr:NULL];
}
