#import "hooks.h"

#import <IOKit/IOKitLib.h>

// IOKit service-probing coverage. Detectors probe the IOKit registry for
// jailbreak-related kernel services / user clients (e.g. IOServiceMatching
// on a known JB service name, or IOServiceOpen on a JB user client). The
// matching dict is inspected for the requested service/class name; a
// JB-indicator name trips the behavioral detector and the probe is answered
// with "no such service" (kIOReturnNotFound / empty iterator) for external
// callers. Only VERIFIED jailbreak service names match — the same
// conservative stance as shdw_bootstrap_service_restricted in mach.x.
static BOOL shdw_iokit_service_name_restricted(const char* name) {
    if(!name || !name[0]) {
        return NO;
    }

    return strcmp(name, "AppleARMBackdoor") == 0
        || strncmp(name, "pongo", 5) == 0
        || strstr(name, "jailbreak") != NULL
        || strstr(name, "jbroot") != NULL;
}

// Inspects an IOServiceMatching/IOServiceNameMatching dict for a restricted
// service/class name. IOServiceMatching sets kIOClassKey; IOServiceNameMatching
// nests the name under kIOPropertyMatchKey -> "IOPropertyName".
static BOOL shdw_iokit_matching_restricted(CFDictionaryRef matching) {
    if(!matching) {
        return NO;
    }

    CFStringRef cls = CFDictionaryGetValue(matching, CFSTR(kIOClassKey));

    if(cls && CFGetTypeID(cls) == CFStringGetTypeID()) {
        char buf[256];

        if(CFStringGetCString(cls, buf, sizeof(buf), kCFStringEncodingUTF8) && shdw_iokit_service_name_restricted(buf)) {
            return YES;
        }
    }

    CFDictionaryRef propMatch = CFDictionaryGetValue(matching, CFSTR(kIOPropertyMatchKey));

    if(propMatch && CFGetTypeID(propMatch) == CFDictionaryGetTypeID()) {
        CFStringRef name = CFDictionaryGetValue(propMatch, CFSTR("IOPropertyName"));

        if(name && CFGetTypeID(name) == CFStringGetTypeID()) {
            char buf[256];

            if(CFStringGetCString(name, buf, sizeof(buf), kCFStringEncodingUTF8) && shdw_iokit_service_name_restricted(buf)) {
                return YES;
            }
        }
    }

    return NO;
}

// Resolves a service object's class name for the IOServiceOpen deny path.
// IORegistryEntryCreateCFProperty is not hooked, so no recursion; the lookup
// only runs for external callers on the deny path.
static BOOL shdw_iokit_service_restricted(io_service_t service) {
    if(!service) {
        return NO;
    }

    CFStringRef cls = IORegistryEntryCreateCFProperty(service, CFSTR(kIOClassKey), kCFAllocatorDefault, 0);

    if(!cls) {
        return NO;
    }

    BOOL restricted = NO;

    if(CFGetTypeID(cls) == CFStringGetTypeID()) {
        char buf[256];

        if(CFStringGetCString(cls, buf, sizeof(buf), kCFStringEncodingUTF8)) {
            restricted = shdw_iokit_service_name_restricted(buf);
        }
    }

    CFRelease(cls);
    return restricted;
}

static kern_return_t (*original_IOServiceGetMatchingServices)(mach_port_t masterPort, CFDictionaryRef matching, io_iterator_t* existing);

// Stock no-match shape for IOServiceGetMatchingServices: kIOReturnSuccess
// with an EMPTY iterator (never kIOReturnNotFound — a stock device answers
// "no such service" with success + an iterator that yields nothing, and a
// caller branching off the error path would see the divergence).
static kern_return_t shdw_iokit_empty_iterator(io_iterator_t* existing) {
    if(!existing) {
        return kIOReturnSuccess;
    }

    // Match against a service name that can never exist; the kernel answers
    // success with an empty iterator.
    CFMutableDictionaryRef none = IOServiceMatching("__shadow_no_such_service__");

    if(none) {
        kern_return_t kr = original_IOServiceGetMatchingServices(MACH_PORT_NULL, none, existing);
        CFRelease(none);

        if(kr == kIOReturnSuccess && existing) {
            return kr;
        }
    }

    *existing = 0;
    return kIOReturnSuccess;
}

static kern_return_t replaced_IOServiceGetMatchingServices(mach_port_t masterPort, CFDictionaryRef matching, io_iterator_t* existing) {
    if(isCallerExternal() && shdw_iokit_matching_restricted(matching)) {
        shdw_detector_detected("iokit");
        return shdw_iokit_empty_iterator(existing);
    }

    return original_IOServiceGetMatchingServices(masterPort, matching, existing);
}

static io_service_t (*original_IOServiceGetMatchingService)(mach_port_t masterPort, CFDictionaryRef matching);
static io_service_t replaced_IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching) {
    if(isCallerExternal() && shdw_iokit_matching_restricted(matching)) {
        shdw_detector_detected("iokit");
        return 0;
    }

    return original_IOServiceGetMatchingService(masterPort, matching);
}

static kern_return_t (*original_IOServiceOpen)(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t* connect);
static kern_return_t replaced_IOServiceOpen(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t* connect) {
    if(isCallerExternal() && shdw_iokit_service_restricted(service)) {
        shdw_detector_detected("iokit");

        if(connect) {
            *connect = 0;
        }

        // Stock shape for an existing service that exposes no openable user
        // client: kIOReturnUnsupported. kIOReturnNotFound would contradict
        // the service object the caller just matched and holds in hand.
        return kIOReturnUnsupported;
    }

    return original_IOServiceOpen(service, owningTask, type, connect);
}

void shadowhook_iokit(HKSubstitutor* hooks) {
    [hooks hookFunction:IOServiceGetMatchingServices withReplacement:replaced_IOServiceGetMatchingServices outOldPtr:(void **) &original_IOServiceGetMatchingServices];
    [hooks hookFunction:IOServiceOpen withReplacement:replaced_IOServiceOpen outOldPtr:(void **) &original_IOServiceOpen];

    // IOServiceGetMatchingService is a stable export; resolve at runtime and
    // skip cleanly when absent (same pattern as the libproc loop in libc.x).
    void* sym = [hooks findSymbolInImage:NULL symbolName:@"_IOServiceGetMatchingService"];

    if(sym) {
        [hooks hookFunction:sym withReplacement:replaced_IOServiceGetMatchingService outOldPtr:(void **) &original_IOServiceGetMatchingService];
    }
}

void shadowhook_iokit_verify(void) {
    shdw_hook_check_t checks[] = {
        { "IOServiceGetMatchingServices", original_IOServiceGetMatchingServices },
        { "IOServiceOpen", original_IOServiceOpen },
    };

    shdw_verify_hooks("iokit", checks, sizeof(checks) / sizeof(checks[0]));
}

// Symbol policy for the iokit C-function group (see dyld.x's
// shdw_sym_policy_table): dlsym must resolve every fishhook-rebound iokit
// export to its replacement for external callers, so the GOT-vs-dlsym
// comparison agrees. Guarded by the original pointer: runtime-resolved
// symbols (IOServiceGetMatchingService) only resolve to their replacement
// when actually installed.
typedef struct {
    const char* name;
    void* replacement;
    void* const* original;
} shdw_iokit_sym_policy_entry_t;

static const shdw_iokit_sym_policy_entry_t shdw_iokit_sym_policy_table[] = {
    { "IOServiceGetMatchingServices", (void*)&replaced_IOServiceGetMatchingServices, (void* const*)&original_IOServiceGetMatchingServices },
    { "IOServiceGetMatchingService", (void*)&replaced_IOServiceGetMatchingService, (void* const*)&original_IOServiceGetMatchingService },
    { "IOServiceOpen", (void*)&replaced_IOServiceOpen, (void* const*)&original_IOServiceOpen },
};

void* shdw_sym_policy_lookup_iokit(const char* name) {
    if(!name) {
        return NULL;
    }

    for(size_t i = 0; i < sizeof(shdw_iokit_sym_policy_table) / sizeof(shdw_iokit_sym_policy_table[0]); i++) {
        if(strcmp(name, shdw_iokit_sym_policy_table[i].name) == 0) {
            if(shdw_iokit_sym_policy_table[i].original && *shdw_iokit_sym_policy_table[i].original == NULL) {
                return NULL;  // runtime-resolved symbol not installed
            }

            return shdw_iokit_sym_policy_table[i].replacement;
        }
    }

    return NULL;
}
