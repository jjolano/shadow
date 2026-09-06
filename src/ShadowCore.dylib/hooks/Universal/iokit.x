#import "UniversalHooks.h"

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

// Property-table exfiltration without a matching-dict probe: a detector
// holding a service object (matched by class, or iterated from the root)
// reads its properties for jailbreak strings (IOPropertyName, version,
// bundle identifiers). IORegistryEntryCreateCFProperty is already used
// internally by shdw_iokit_service_restricted above, so only filter when
// the RESULT carries a restricted string — never the whole table (a NULL
// whole-table answer for a live service contradicts the handle in hand).
// Only VERIFIED jailbreak tokens match (same stance as the service-name
// gate); stock property values pass through byte-identical.
static BOOL shdw_iokit_property_value_restricted(CFTypeRef value) {
    if(!value) return NO;
    CFTypeID stringID = CFStringGetTypeID();
    if(CFGetTypeID(value) == stringID) {
        char buf[256];
        if(CFStringGetCString((CFStringRef)value, buf, sizeof(buf), kCFStringEncodingUTF8))
            return shdw_iokit_service_name_restricted(buf);
        return NO;
    }
    if(CFGetTypeID(value) == CFArrayGetTypeID()) {
        CFIndex n = CFArrayGetCount((CFArrayRef)value);
        if(n < 0 || n > 128) return NO;  // malformed: fail open
        for(CFIndex i = 0; i < n; i++)
            if(shdw_iokit_property_value_restricted(CFArrayGetValueAtIndex((CFArrayRef)value, i)))
                return YES;
        return NO;
    }
    if(CFGetTypeID(value) == CFDictionaryGetTypeID()) {
        CFIndex n = CFDictionaryGetCount((CFDictionaryRef)value);
        if(n <= 0 || n > 64) return NO;  // malformed: fail open
        const void* keys[64];
        const void* vals[64];
        CFDictionaryGetKeysAndValues((CFDictionaryRef)value, keys, vals);
        for(CFIndex i = 0; i < n; i++)
            if(shdw_iokit_property_value_restricted(vals[i])) return YES;
        return NO;
    }
    return NO;
}

static CFTypeRef (*original_IORegistryEntryCreateCFProperty)(io_service_t service, CFStringRef key, CFAllocatorRef allocator, IOOptionBits options);
static CFTypeRef replaced_IORegistryEntryCreateCFProperty(io_service_t service, CFStringRef key, CFAllocatorRef allocator, IOOptionBits options) {
    CFTypeRef result = original_IORegistryEntryCreateCFProperty(service, key, allocator, options);
    if(isCallerExternal() && result && shdw_iokit_property_value_restricted(result)) {
        CFRelease(result);
        return NULL;  // stock shape for an absent property
    }
    return result;
}

static kern_return_t (*original_IORegistryEntryCreateCFProperties)(io_service_t service, CFMutableDictionaryRef* properties, CFAllocatorRef allocator, IOOptionBits options);
static kern_return_t replaced_IORegistryEntryCreateCFProperties(io_service_t service, CFMutableDictionaryRef* properties, CFAllocatorRef allocator, IOOptionBits options) {
    kern_return_t kr = original_IORegistryEntryCreateCFProperties(service, properties, allocator, options);
    if(!isCallerExternal() || kr != kIOReturnSuccess || !properties || !*properties) return kr;
    // Strip restricted values key-by-key; an emptied table stays a valid
    // (empty) table — never a NULL table for a live service.
    CFMutableDictionaryRef table = *properties;
    CFIndex n = CFDictionaryGetCount(table);
    if(n <= 0 || n > 256) return kr;  // malformed: fail open
    const void* keys[256];
    const void* vals[256];
    CFDictionaryGetKeysAndValues(table, keys, vals);
    for(CFIndex i = 0; i < n; i++)
        if(shdw_iokit_property_value_restricted(vals[i]))
            CFDictionaryRemoveValue(table, keys[i]);
    return kr;
}

static CFTypeRef (*original_IORegistryEntrySearchCFProperty)(io_service_t service, const io_name_t plane, CFStringRef key, CFAllocatorRef allocator, IOOptionBits options);
static CFTypeRef replaced_IORegistryEntrySearchCFProperty(io_service_t service, const io_name_t plane, CFStringRef key, CFAllocatorRef allocator, IOOptionBits options) {
    CFTypeRef result = original_IORegistryEntrySearchCFProperty(service, plane, key, allocator, options);
    if(isCallerExternal() && result && shdw_iokit_property_value_restricted(result)) {
        CFRelease(result);
        return NULL;
    }
    return result;
}

void shdw_universal_iokit(SHDWHookSession* hooks) {
    [hooks hookFunction:IOServiceGetMatchingServices withReplacement:replaced_IOServiceGetMatchingServices outOldPtr:(void **) &original_IOServiceGetMatchingServices];
    [hooks hookFunction:IOServiceOpen withReplacement:replaced_IOServiceOpen outOldPtr:(void **) &original_IOServiceOpen];

    // IOServiceGetMatchingService is a stable export; resolve at runtime and
    // skip cleanly when absent (same pattern as the libproc loop in libc.x).
    // shdw_resolve_libsystem = dlsym hash lookup; findSymbolInImage:NULL walked
    // all ~600 loaded images and was pathologically slow (see hooks.h).
    void* sym = shdw_resolve_libsystem("_IOServiceGetMatchingService");

    if(sym) {
        [hooks hookFunction:sym withReplacement:replaced_IOServiceGetMatchingService outOldPtr:(void **) &original_IOServiceGetMatchingService];
    }

    // Property-table exfiltration (see above): stable IOKitLib exports,
    // resolved at runtime and skipped cleanly when absent.
    sym = shdw_resolve_libsystem("_IORegistryEntryCreateCFProperty");
    if(sym) {
        [hooks hookFunction:sym withReplacement:replaced_IORegistryEntryCreateCFProperty outOldPtr:(void **) &original_IORegistryEntryCreateCFProperty];
    }
    sym = shdw_resolve_libsystem("_IORegistryEntryCreateCFProperties");
    if(sym) {
        [hooks hookFunction:sym withReplacement:replaced_IORegistryEntryCreateCFProperties outOldPtr:(void **) &original_IORegistryEntryCreateCFProperties];
    }
    sym = shdw_resolve_libsystem("_IORegistryEntrySearchCFProperty");
    if(sym) {
        [hooks hookFunction:sym withReplacement:replaced_IORegistryEntrySearchCFProperty outOldPtr:(void **) &original_IORegistryEntrySearchCFProperty];
    }
}

void shdw_universal_iokit_verify(void) {
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
    { "IORegistryEntryCreateCFProperties", (void*)&replaced_IORegistryEntryCreateCFProperties, (void* const*)&original_IORegistryEntryCreateCFProperties },
    { "IORegistryEntryCreateCFProperty", (void*)&replaced_IORegistryEntryCreateCFProperty, (void* const*)&original_IORegistryEntryCreateCFProperty },
    { "IORegistryEntrySearchCFProperty", (void*)&replaced_IORegistryEntrySearchCFProperty, (void* const*)&original_IORegistryEntrySearchCFProperty },
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
