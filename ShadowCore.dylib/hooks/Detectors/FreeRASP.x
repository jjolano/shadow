#import "hooks.h"
static BOOL shdw_freeRASP_enabled = YES;
static mach_msg_return_t (*shdw_freeRASP_originalMachMsg)(mach_msg_header_t*, mach_msg_option_t,
    mach_msg_size_t, mach_msg_size_t, mach_port_name_t, mach_msg_timeout_t, mach_port_name_t) = NULL;
static BOOL (*shdw_freeRASP_originalEncryptedBinary)(void) = NULL;

static BOOL shdw_freeRASP_isEncryptedBinary(void) {
    return YES;
}

static BOOL shdw_freeRASP_isVersion712(const struct mach_header* header) {
    static const uint8_t expectedUUID[16] = {
        0x30, 0x3f, 0x80, 0xd6, 0x66, 0x3d, 0x3b, 0xa7,
        0x92, 0x07, 0x6f, 0x97, 0x80, 0xea, 0xe3, 0xa2,
    };
    if(!header || header->magic != MH_MAGIC_64) return NO;

    const struct load_command* command = (const void*)((const struct mach_header_64*)header + 1);
    const uint8_t* end = (const uint8_t*)command + header->sizeofcmds;
    for(uint32_t i = 0; i < header->ncmds; i++) {
        if((const uint8_t*)command + sizeof(*command) > end ||
           command->cmdsize < sizeof(*command) || (const uint8_t*)command + command->cmdsize > end) return NO;
        if(command->cmd == LC_UUID && command->cmdsize >= sizeof(struct uuid_command)) {
            return memcmp(((const struct uuid_command*)command)->uuid, expectedUUID, sizeof(expectedUUID)) == 0;
        }
        command = (const void*)((const uint8_t*)command + command->cmdsize);
    }
    return NO;
}

static void shdw_freeRASP_installEncryptedBinary(SHDWHookSession* hooks) {
    static const uint8_t expectedPrologue[] = { 0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91 };
    if(shdw_freeRASP_originalEncryptedBinary) return;

    for(uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char* name = _dyld_get_image_name(i);
        const struct mach_header* header = _dyld_get_image_header(i);
        if(!name || !strstr(name, "/TalsecRuntime.framework/TalsecRuntime") ||
           !shdw_freeRASP_isVersion712(header)) continue;

        void* target = (uint8_t*)header + 0x4c90;
        if(memcmp(target, expectedPrologue, sizeof(expectedPrologue)) != 0) return;
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

void shadowhook_FreeRASP(SHDWHookSession* hooks) {
    if(!shdw_freeRASP_originalMachMsg) {
        if(![hooks hookFunction:mach_msg withReplacement:shdw_freeRASP_machMsg
                      outOldPtr:(void**)&shdw_freeRASP_originalMachMsg]) {
            [hooks hookRebindSymbol:@"mach_msg" withReplacement:shdw_freeRASP_machMsg
                          outOldPtr:(void**)&shdw_freeRASP_originalMachMsg];
        }
    }
    shdw_freeRASP_installEncryptedBinary(hooks);
}

// freeRASP emits inline raw svc calls. Select the generic syscall coverage;
// its write probes use the detector-gated stock sandbox policy. Talsec.start
// is never replaced or suppressed.
void shadowhook_FreeRASP_preparePreferences(NSMutableDictionary* prefs) {
    shdw_freeRASP_enabled = YES;
    prefs[SHDWHookIDSyscall] = @YES;
}

BOOL shadowhook_FreeRASP_shouldHideExistencePath(NSString* path) {
    return ([path isEqualToString:@"/.file"] || [path isEqualToString:@"/usr/sbin/cfprefsd"]);
}

__attribute__((visibility("default")))
BOOL shdw_detector_path_policy_is_restricted(const char* path) {
    return path && (strcmp(path, "/.file") == 0 || strcmp(path, "/usr/sbin/cfprefsd") == 0);
}
