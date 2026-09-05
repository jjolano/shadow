#import "AdapterHooks.h"
static BOOL shdw_freeRASP_enabled = YES;
static BOOL shdw_freeRASP_active = NO;
static mach_msg_return_t (*shdw_freeRASP_originalMachMsg)(mach_msg_header_t*, mach_msg_option_t,
    mach_msg_size_t, mach_msg_size_t, mach_port_name_t, mach_msg_timeout_t, mach_port_name_t) = NULL;
static BOOL (*shdw_freeRASP_originalEncryptedBinary)(void) = NULL;

static BOOL shdw_freeRASP_isEncryptedBinary(void) {
    return YES;
}

// Per-version hook table. Talsec exports none of its own symbols and its
// classes are pure Swift (no ObjC methods), so dynamic lookup is impossible;
// the 8-byte prologues collide with hundreds of unrelated functions, so
// offset + prologue-verify keyed by the image LC_UUID is the only sound
// anchor. Supporting a new Talsec version is a data row, not a logic change:
// read the LC_UUID (otool -l), then one-time RE the two function offsets and
// their first 8 bytes, and append below. Unknown UUIDs install nothing
// (fail-safe: the row simply stays red until pinned).
typedef struct {
    uint8_t uuid[16];
    uint32_t encryptedBinaryOffset;
    uint8_t encryptedBinaryPrologue[8];
    uint32_t deliverOffset;
    uint8_t deliverPrologue[8];
} shdw_freeRASP_version_t;

static const shdw_freeRASP_version_t shdw_freeRASP_versions[] = {
    {   // TalsecRuntime 7.1.2
        .uuid = {
            0x30, 0x3f, 0x80, 0xd6, 0x66, 0x3d, 0x3b, 0xa7,
            0x92, 0x07, 0x6f, 0x97, 0x80, 0xea, 0xe3, 0xa2,
        },
        .encryptedBinaryOffset = 0x4c90,
        .encryptedBinaryPrologue = { 0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91 },
        .deliverOffset = 0x3d534,
        .deliverPrologue = { 0xff, 0x03, 0x01, 0xd1, 0xf6, 0x57, 0x01, 0xa9 },
    },
};
#define SHDW_FREERASP_VERSION_COUNT (sizeof(shdw_freeRASP_versions) / sizeof(shdw_freeRASP_versions[0]))

static const shdw_freeRASP_version_t* shdw_freeRASP_versionForHeader(const struct mach_header* header) {
    if(!header || header->magic != MH_MAGIC_64) return NULL;

    const struct load_command* command = (const void*)((const struct mach_header_64*)header + 1);
    const uint8_t* end = (const uint8_t*)command + header->sizeofcmds;
    for(uint32_t i = 0; i < header->ncmds; i++) {
        if((const uint8_t*)command + sizeof(*command) > end ||
           command->cmdsize < sizeof(*command) || (const uint8_t*)command + command->cmdsize > end) return NULL;
        if(command->cmd == LC_UUID && command->cmdsize >= sizeof(struct uuid_command)) {
            const uint8_t* uuid = ((const struct uuid_command*)command)->uuid;
            for(unsigned v = 0; v < SHDW_FREERASP_VERSION_COUNT; v++) {
                if(memcmp(uuid, shdw_freeRASP_versions[v].uuid, sizeof(shdw_freeRASP_versions[v].uuid)) == 0) {
                    return &shdw_freeRASP_versions[v];
                }
            }
            return NULL;
        }
        command = (const void*)((const uint8_t*)command + command->cmdsize);
    }
    return NULL;
}

static void shdw_freeRASP_installEncryptedBinary(SHDWHookSession* hooks) {
    if(shdw_freeRASP_originalEncryptedBinary) return;

    for(uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char* name = _dyld_get_image_name(i);
        const struct mach_header* header = _dyld_get_image_header(i);
        if(!name || !strstr(name, "/TalsecRuntime.framework/TalsecRuntime")) continue;
        const shdw_freeRASP_version_t* version = shdw_freeRASP_versionForHeader(header);
        if(!version) continue;

        void* target = (uint8_t*)header + version->encryptedBinaryOffset;
        if(memcmp(target, version->encryptedBinaryPrologue, sizeof(version->encryptedBinaryPrologue)) != 0) return;
        [hooks hookFunction:target withReplacement:shdw_freeRASP_isEncryptedBinary
                  outOldPtr:(void**)&shdw_freeRASP_originalEncryptedBinary];
        return;
    }
}

static mach_msg_return_t shdw_freeRASP_machMsg(mach_msg_header_t* msg, mach_msg_option_t option,
    mach_msg_size_t sendSize, mach_msg_size_t receiveLimit, mach_port_name_t receiveName,
    mach_msg_timeout_t timeout, mach_port_name_t notify) {
    uint64_t marker = 0;
    if(shdw_freeRASP_enabled && msg && (option & MACH_SEND_MSG) && sendSize == 40 &&
       msg->msgh_bits == 0x1513 && msg->msgh_id == 0x400000ce) {
        memcpy(&marker, (uint8_t*)msg + 24, sizeof(marker));
        if(marker == 0x444f50414d494e45ULL && isCallerExternal()) return MACH_SEND_INVALID_DEST;
    }
    return shdw_freeRASP_originalMachMsg(msg, option, sendSize, receiveLimit,
        receiveName, timeout, notify);
}

static BOOL shdw_adapter_freerasp_hides_path(NSString* path) {
    return shdw_freeRASP_active &&
        ([path isEqualToString:@"/.file"] || [path isEqualToString:@"/usr/sbin/cfprefsd"]);
}

// Threat-delivery function (per-version offset in the table above): dequeues
// a SecurityThreat and invokes the app's handler. The threat's enum ordinal
// is at [threat + 0x38]. privilegedAccess (ordinal 1) is Talsec's own
// aggregate jailbreak verdict — it resists every stealth/emulation/debugger
// attempt to pin its exact input (the checks queue asynchronously), so under
// aggressive mode suppress its delivery outright: skip the handler call for
// that one ordinal, matching what Shadow would achieve if it could
// neutralise the underlying probe. All other threats pass through untouched.
#define SHDW_FREERASP_THREAT_PRIVILEGED_ACCESS 1
static void (*shdw_freeRASP_origDeliver)(void* threat, void* a1, void* a2) = NULL;
static void shdw_freeRASP_deliver(void* threat, void* a1, void* a2) {
    if(threat && *((unsigned char*)threat + 0x38) == SHDW_FREERASP_THREAT_PRIVILEGED_ACCESS &&
       shdw_freeRASP_enabled && shdw_detector_aggressive) {
        return;  // drop privilegedAccess: do not deliver to the handler
    }
    if(shdw_freeRASP_origDeliver) shdw_freeRASP_origDeliver(threat, a1, a2);
}
static void shdw_freeRASP_installDeliver(SHDWHookSession* hooks) {
    if(shdw_freeRASP_origDeliver) return;
    for(uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char* name = _dyld_get_image_name(i);
        const struct mach_header* header = _dyld_get_image_header(i);
        if(!name || !strstr(name, "/TalsecRuntime.framework/TalsecRuntime")) continue;
        const shdw_freeRASP_version_t* version = shdw_freeRASP_versionForHeader(header);
        if(!version) continue;
        void* target = (uint8_t*)header + version->deliverOffset;
        if(memcmp(target, version->deliverPrologue, sizeof(version->deliverPrologue)) != 0) return;
        [hooks hookFunction:target withReplacement:shdw_freeRASP_deliver
                  outOldPtr:(void**)&shdw_freeRASP_origDeliver];
        return;
    }
}

void shdw_adapter_freerasp(SHDWHookSession* hooks) {
    shdw_freeRASP_active = YES;
    SHDWSetAdapterPathPredicate(shdw_adapter_freerasp_hides_path);
    if(!shdw_freeRASP_originalMachMsg) {
        if(![hooks hookFunction:mach_msg withReplacement:shdw_freeRASP_machMsg
                      outOldPtr:(void**)&shdw_freeRASP_originalMachMsg]) {
            [hooks hookRebindSymbol:@"mach_msg" withReplacement:shdw_freeRASP_machMsg
                          outOldPtr:(void**)&shdw_freeRASP_originalMachMsg];
        }
    }
    // isEncryptedBinary() is one of Talsec's own check functions; forcing its
    // return is a disable-style neutralizer, so it is gated on the user's
    // aggressive opt-in. The mach_msg / path-hiding above are natural (they
    // shape neutral APIs to their stock answers) and always run.
    if(shdw_detector_aggressive) {
        shdw_freeRASP_installEncryptedBinary(hooks);
        shdw_freeRASP_installDeliver(hooks);
    }
}

// freeRASP emits inline raw svc calls. Select the generic syscall coverage;
// its write probes use the detector-gated stock sandbox policy. Talsec.start
// is never replaced or suppressed.
void shdw_adapter_freerasp_prepare_preferences(NSMutableDictionary* prefs) {
    shdw_freeRASP_enabled = YES;
    prefs[SHDWUniversalSyscallID] = @YES;
}
