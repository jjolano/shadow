#import "AdapterHooks.h"

// BATJailbreakGuard's PreventedAPIs check asks whether libSystem symbols
// (system / posix_spawn / dlopen / dlsym) resolve via dlsym(RTLD_DEFAULT, …).
// They resolve on a pristine, un-jailbroken App Store device too, so the check
// flags stock iOS — a self-invalidating signal, not evidence of Shadow or the
// jailbreak. No stock-shaped ("natural") answer clears it without also lying to
// a legitimate app, so neutralising it is disable-style: only under aggressive
// mode do we force its verdict to false.
//
// Anchor (rebuild-stable, no hardcoded offsets): the check's public entry point
// `JailbreakDetectionPreventedAPICheckService.isJailbreakDetected()` is exported
// in the Swift trie, so dlsym resolves it by mangled name. The optimiser leaves
// that symbol as a one-instruction thunk that `b`-branches to the real function
// body; the app's devirtualised call site calls the BODY directly, not the
// thunk, so we follow the thunk's branch to the body and entry-patch that. Both
// the module token (test runner vs SPM embed) and Swift's abbreviated name
// spelling are handled below. dlsym only resolves in a process that links BAT,
// so this adapter is a no-op everywhere else.

static BOOL shdw_bat_isJailbroken_false(void* self, void* sel) {
    return NO;  // Swift () -> Bool; w0 = 0
}

// Follow a single AArch64 unconditional `B` (opcode 0b000101, imm26<<2,
// sign-extended). Returns the branch target, or the thunk itself if the first
// instruction is not a plain B (already the body — hook it directly).
static void* shdw_bat_follow_branch(void* thunk) {
    uint32_t word = *(const uint32_t*)thunk;
    if((word >> 26) != 0x05) return thunk;  // not an unconditional B
    int32_t imm26 = word & 0x03ffffff;
    if(imm26 & (1 << 25)) imm26 |= ~0x03ffffff;  // sign-extend
    return (uint8_t*)thunk + ((intptr_t)imm26 << 2);
}

// isJailbreakDetected mangled as
//   $s<module>42JailbreakDetectionPreventedAPICheckServiceC02isD8DetectedSbyF
// where <module> is a length-prefixed token. Swift abbreviates the repeated
// "JailbreakDetection…" substring, hence the "02isD8Detected" spelling.
static const char* const kSHDWBATModulePrefixes[] = {
    "23BATJailbreakGuardRunner",  // test runner target
    "17BATJailbreakGuard",        // SPM module embed
};

static void shdw_bat_install_preventedapis(SHDWHookSession* hooks) {
    static const uint8_t prefixCount = sizeof(kSHDWBATModulePrefixes) / sizeof(kSHDWBATModulePrefixes[0]);
    for(uint8_t p = 0; p < prefixCount; p++) {
        // dlsym takes the symbol without its leading underscore.
        char name[256];
        snprintf(name, sizeof(name),
                 "$s%s42JailbreakDetectionPreventedAPICheckServiceC02isD8DetectedSbyF",
                 kSHDWBATModulePrefixes[p]);
        void* thunk = dlsym(RTLD_DEFAULT, name);
        if(!thunk) continue;
        void* body = shdw_bat_follow_branch(thunk);
        [hooks hookFunction:body withReplacement:shdw_bat_isJailbroken_false outOldPtr:NULL];
        return;
    }
}

void shdw_adapter_batjailbreakguard(SHDWHookSession* hooks) {
    // Disable-style: only neutralise the flawed check when the user opts into
    // aggressive mode (globally or per app). Natural mode leaves it untouched.
    if(shdw_detector_aggressive) {
        shdw_bat_install_preventedapis(hooks);
    }
}
