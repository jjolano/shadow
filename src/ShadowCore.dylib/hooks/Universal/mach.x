#import "UniversalHooks.h"

// Single shared bootstrap-service matcher for every bootstrap hook in this
// file and for the sandbox_check mach-lookup denial in sandbox.x (extern
// declared at the top of that file — deliberately NOT in hooks.h). Only
// VERIFIED jailbreak service names/prefixes match; the overbroad "com.ex"
// prefix is gone. The tweak's own "me.jjolano" umbrella is included so its
// package namespace is not exposed to external callers.
BOOL shdw_bootstrap_service_restricted(const char* name) {
    if(!name) {
        return NO;
    }

    return strstr(name, "cy:") == name
        || strstr(name, "lh:") == name
        || strstr(name, "rbs:") == name
        || strstr(name, "org.coolstar") == name
        || strstr(name, "org.saurik") == name
        || strstr(name, "com.saurik") == name
        || strstr(name, "com.opa334") == name
        || strstr(name, "me.jjolano") == name
        || strstr(name, "jailbreakd") == name;
}

// Hides a right obtained from a SUCCESSFUL bootstrap call: deallocates the
// send right we own, clears the output port, and reports the stock
// sandbox-denied error. Never fabricates a failure over a real one — the
// callers only reach this after the original SUCCEEDED.
//
// The code returned must match what a stock, sandboxed app sees when it looks
// up a service it is not entitled to reach. On iOS that is
// BOOTSTRAP_NOT_PRIVILEGED (1100), NOT BOOTSTRAP_UNKNOWN_SERVICE (1102):
// launchd knows the name but the sandbox denies the lookup, so the caller gets
// "not privileged", not "no such service". Some detectors treat 1102 (and even
// success) as jailbreak evidence while 1100 is the ordinary sandbox answer, so
// returning the true stock code both conceals the right and avoids the
// fingerprint of the wrong failure mode.
#ifndef BOOTSTRAP_NOT_PRIVILEGED
#define BOOTSTRAP_NOT_PRIVILEGED 1100
#endif
static kern_return_t shdw_bootstrap_hide_right(mach_port_t* sp) {
    if(sp && *sp != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), *sp);
        *sp = MACH_PORT_NULL;
    }

    return BOOTSTRAP_NOT_PRIVILEGED;
}

// Normalises a completed bootstrap_look_up for a restricted service name to the
// stock sandbox-denied shape. A jailbreak that registers these names makes the
// lookup SUCCEED (a live send right) — hidden via shdw_bootstrap_hide_right.
// But the jailbreak's launchd can also answer a KNOWN name with a non-stock
// error such as BOOTSTRAP_UNKNOWN_SERVICE (1102); a probe that reads 1102 (or
// success) as jailbreak evidence and only 1100 as clean then still fires. For a
// restricted name, collapse EITHER outcome to the single stock code a
// sandboxed app sees for a service it may not reach: BOOTSTRAP_NOT_PRIVILEGED.
static kern_return_t shdw_bootstrap_normalize_lookup(kern_return_t result, const char* service_name, mach_port_t* sp) {
    if(!shdw_bootstrap_service_restricted(service_name)) {
        return result;
    }
    if(result == KERN_SUCCESS) {
        return shdw_bootstrap_hide_right(sp);
    }
    // Any non-stock failure code for a name we conceal is itself a tell.
    return BOOTSTRAP_NOT_PRIVILEGED;
}

static kern_return_t (*original_bootstrap_check_in)(mach_port_t bp, const char* service_name, mach_port_t* sp);
static kern_return_t replaced_bootstrap_check_in(mach_port_t bp, const char* service_name, mach_port_t* sp) {
    if(!isCallerExternal()) {
        return original_bootstrap_check_in(bp, service_name, sp);
    }

    kern_return_t result = original_bootstrap_check_in(bp, service_name, sp);

    if(result == KERN_SUCCESS && shdw_bootstrap_service_restricted(service_name)) {
        return shdw_bootstrap_hide_right(sp);
    }

    return result;
}

static kern_return_t (*original_bootstrap_look_up)(mach_port_t bp, const char* service_name, mach_port_t* sp);
static kern_return_t replaced_bootstrap_look_up(mach_port_t bp, const char* service_name, mach_port_t* sp) {
    if(!isCallerExternal()) {
        return original_bootstrap_look_up(bp, service_name, sp);
    }

    kern_return_t result = original_bootstrap_look_up(bp, service_name, sp);

    return shdw_bootstrap_normalize_lookup(result, service_name, sp);
}

// --- bootstrap *2/*3/per_user siblings (private libxpc API, runtime-
// resolved; skipped cleanly when absent) ---

// Prototypes for the private libxpc bootstrap variants (not in the SDK's
// public bootstrap.h).
extern kern_return_t bootstrap_check_in2(mach_port_t bp, const char* service_name, uint64_t flags, mach_port_t* sp);
extern kern_return_t bootstrap_check_in3(mach_port_t bp, const char* service_name, uint64_t flags, mach_port_t* sp, uint64_t* flags_out);
extern kern_return_t bootstrap_look_up2(mach_port_t bp, const char* service_name, mach_port_t* sp, pid_t target_pid, uint64_t flags);
extern kern_return_t bootstrap_look_up3(mach_port_t bp, const char* service_name, mach_port_t* sp, pid_t target_pid, uint64_t flags, uint64_t* flags_out);
extern kern_return_t bootstrap_look_up_per_user(mach_port_t bp, const char* service_name, uid_t user_id, mach_port_t* sp);

static kern_return_t (*original_bootstrap_check_in2)(mach_port_t bp, const char* service_name, uint64_t flags, mach_port_t* sp);
static kern_return_t replaced_bootstrap_check_in2(mach_port_t bp, const char* service_name, uint64_t flags, mach_port_t* sp) {
    if(!isCallerExternal()) {
        return original_bootstrap_check_in2(bp, service_name, flags, sp);
    }

    kern_return_t result = original_bootstrap_check_in2(bp, service_name, flags, sp);

    if(result == KERN_SUCCESS && shdw_bootstrap_service_restricted(service_name)) {
        return shdw_bootstrap_hide_right(sp);
    }

    return result;
}

static kern_return_t (*original_bootstrap_check_in3)(mach_port_t bp, const char* service_name, uint64_t flags, mach_port_t* sp, uint64_t* flags_out);
static kern_return_t replaced_bootstrap_check_in3(mach_port_t bp, const char* service_name, uint64_t flags, mach_port_t* sp, uint64_t* flags_out) {
    if(!isCallerExternal()) {
        return original_bootstrap_check_in3(bp, service_name, flags, sp, flags_out);
    }

    kern_return_t result = original_bootstrap_check_in3(bp, service_name, flags, sp, flags_out);

    if(result == KERN_SUCCESS && shdw_bootstrap_service_restricted(service_name)) {
        return shdw_bootstrap_hide_right(sp);
    }

    return result;
}

static kern_return_t (*original_bootstrap_look_up2)(mach_port_t bp, const char* service_name, mach_port_t* sp, pid_t target_pid, uint64_t flags);
static kern_return_t replaced_bootstrap_look_up2(mach_port_t bp, const char* service_name, mach_port_t* sp, pid_t target_pid, uint64_t flags) {
    if(!isCallerExternal()) {
        return original_bootstrap_look_up2(bp, service_name, sp, target_pid, flags);
    }

    kern_return_t result = original_bootstrap_look_up2(bp, service_name, sp, target_pid, flags);

    return shdw_bootstrap_normalize_lookup(result, service_name, sp);
}

static kern_return_t (*original_bootstrap_look_up3)(mach_port_t bp, const char* service_name, mach_port_t* sp, pid_t target_pid, uint64_t flags, uint64_t* flags_out);
static kern_return_t replaced_bootstrap_look_up3(mach_port_t bp, const char* service_name, mach_port_t* sp, pid_t target_pid, uint64_t flags, uint64_t* flags_out) {
    if(!isCallerExternal()) {
        return original_bootstrap_look_up3(bp, service_name, sp, target_pid, flags, flags_out);
    }

    kern_return_t result = original_bootstrap_look_up3(bp, service_name, sp, target_pid, flags, flags_out);

    return shdw_bootstrap_normalize_lookup(result, service_name, sp);
}

static kern_return_t (*original_bootstrap_look_up_per_user)(mach_port_t bp, const char* service_name, uid_t user_id, mach_port_t* sp);
static kern_return_t replaced_bootstrap_look_up_per_user(mach_port_t bp, const char* service_name, uid_t user_id, mach_port_t* sp) {
    if(!isCallerExternal()) {
        return original_bootstrap_look_up_per_user(bp, service_name, user_id, sp);
    }

    kern_return_t result = original_bootstrap_look_up_per_user(bp, service_name, user_id, sp);

    return shdw_bootstrap_normalize_lookup(result, service_name, sp);
}

// --- pass-through surfaces (conservative; see each comment) ---

// pid_for_task: pass-through. The pid of a task port can only leak to a
// caller that already holds a foreign task port, and foreign task-port
// acquisition is gated at task_for_pid. libxpc legitimately resolves peer
// pids from ports received over bootstrap, so denying here would break XPC.
static kern_return_t (*original_pid_for_task)(task_port_t task, pid_t* pid);
static kern_return_t replaced_pid_for_task(task_port_t task, pid_t* pid) {
    return original_pid_for_task(task, pid);
}

// mach_port_names: pass-through (conservative). Port NAME integers cannot be
// attributed to restricted images without introspecting every right, and the
// JB service acquisition this would expose is already gated at
// bootstrap_look_up/task_for_pid. TODO: filter rights attributable to
// restricted images once a per-port attribution exists; deallocate removed
// rights and rebuild the arrays.
static kern_return_t (*original_mach_port_names)(ipc_space_t task, mach_port_name_array_t* names, mach_msg_type_number_t* namesCnt, mach_port_type_array_t* types, mach_msg_type_number_t* typesCnt);
static kern_return_t replaced_mach_port_names(ipc_space_t task, mach_port_name_array_t* names, mach_msg_type_number_t* namesCnt, mach_port_type_array_t* types, mach_msg_type_number_t* typesCnt) {
    return original_mach_port_names(task, names, namesCnt, types, typesCnt);
}

void shdw_universal_mach_bootstrap(SHDWHookSession* hooks) {
    // Rebind bootstrap_check_in / bootstrap_look_up through the IMPORT-SLOT
    // lane, not an ElleKit entry patch. The public `bootstrap_look_up` is a
    // libSystem re-export of a libxpc entry; entry-patching its shared-cache
    // text does NOT intercept an injected app whose own lazy-bound stub reaches
    // the function through a different path (observed decisively: a runner's
    // bootstrap_look_up("cy:…") still returned the live 1102 while access()
    // hooks in the same call frame — installed via this rebind lane — were
    // filtered, and a magic-name sentinel in the entry-patched replacement
    // never fired). Rewriting the caller's import pointer catches the call
    // wherever the implementation lives, the same way `access` is hooked.
    [hooks hookRebindSymbol:@"bootstrap_check_in" withReplacement:(void*)replaced_bootstrap_check_in outOldPtr:(void **) &original_bootstrap_check_in];
    [hooks hookRebindSymbol:@"bootstrap_look_up" withReplacement:(void*)replaced_bootstrap_look_up outOldPtr:(void **) &original_bootstrap_look_up];

    // Runtime-resolve the private siblings; skip cleanly when absent.
    void* sym = shdw_resolve_libsystem("_bootstrap_check_in2");
    if(sym) [hooks hookFunction:sym withReplacement:replaced_bootstrap_check_in2 outOldPtr:(void **) &original_bootstrap_check_in2];

    sym = shdw_resolve_libsystem("_bootstrap_check_in3");
    if(sym) [hooks hookFunction:sym withReplacement:replaced_bootstrap_check_in3 outOldPtr:(void **) &original_bootstrap_check_in3];

    sym = shdw_resolve_libsystem("_bootstrap_look_up2");
    if(sym) [hooks hookFunction:sym withReplacement:replaced_bootstrap_look_up2 outOldPtr:(void **) &original_bootstrap_look_up2];

    sym = shdw_resolve_libsystem("_bootstrap_look_up3");
    if(sym) [hooks hookFunction:sym withReplacement:replaced_bootstrap_look_up3 outOldPtr:(void **) &original_bootstrap_look_up3];

    sym = shdw_resolve_libsystem("_bootstrap_look_up_per_user");
    if(sym) [hooks hookFunction:sym withReplacement:replaced_bootstrap_look_up_per_user outOldPtr:(void **) &original_bootstrap_look_up_per_user];

    sym = shdw_resolve_libsystem("_pid_for_task");
    if(sym) [hooks hookFunction:sym withReplacement:replaced_pid_for_task outOldPtr:(void **) &original_pid_for_task];

    sym = shdw_resolve_libsystem("_mach_port_names");
    if(sym) [hooks hookFunction:sym withReplacement:replaced_mach_port_names outOldPtr:(void **) &original_mach_port_names];
}

void shdw_universal_mach_bootstrap_verify(void) {
    shdw_hook_check_t checks[] = {
        { "bootstrap_check_in", original_bootstrap_check_in },
        { "bootstrap_look_up", original_bootstrap_look_up },
    };

    shdw_verify_hooks("mach", checks, sizeof(checks) / sizeof(checks[0]));
}

// Symbol policy for the mach C-function group (see dyld.x's
// shdw_sym_policy_table): dlsym must resolve every fishhook-rebound mach
// export to its replacement for external callers, so the GOT-vs-dlsym
// comparison agrees. Guarded by the original pointer: runtime-resolved
// private siblings (bootstrap_*2/3, pid_for_task, mach_port_names) only
// resolve to their replacement when actually installed.
typedef struct {
    const char* name;
    void* replacement;
    void* const* original;
} shdw_mach_sym_policy_entry_t;

static const shdw_mach_sym_policy_entry_t shdw_mach_sym_policy_table[] = {
    { "bootstrap_check_in", (void*)&replaced_bootstrap_check_in, (void* const*)&original_bootstrap_check_in },
    { "bootstrap_check_in2", (void*)&replaced_bootstrap_check_in2, (void* const*)&original_bootstrap_check_in2 },
    { "bootstrap_check_in3", (void*)&replaced_bootstrap_check_in3, (void* const*)&original_bootstrap_check_in3 },
    { "bootstrap_look_up", (void*)&replaced_bootstrap_look_up, (void* const*)&original_bootstrap_look_up },
    { "bootstrap_look_up2", (void*)&replaced_bootstrap_look_up2, (void* const*)&original_bootstrap_look_up2 },
    { "bootstrap_look_up3", (void*)&replaced_bootstrap_look_up3, (void* const*)&original_bootstrap_look_up3 },
    { "bootstrap_look_up_per_user", (void*)&replaced_bootstrap_look_up_per_user, (void* const*)&original_bootstrap_look_up_per_user },
    { "mach_port_names", (void*)&replaced_mach_port_names, (void* const*)&original_mach_port_names },
    { "pid_for_task", (void*)&replaced_pid_for_task, (void* const*)&original_pid_for_task },
};

void* shdw_sym_policy_lookup_mach(const char* name) {
    if(!name) {
        return NULL;
    }

    for(size_t i = 0; i < sizeof(shdw_mach_sym_policy_table) / sizeof(shdw_mach_sym_policy_table[0]); i++) {
        if(strcmp(name, shdw_mach_sym_policy_table[i].name) == 0) {
            if(shdw_mach_sym_policy_table[i].original && *shdw_mach_sym_policy_table[i].original == NULL) {
                return NULL;  // runtime-resolved symbol not installed
            }

            return shdw_mach_sym_policy_table[i].replacement;
        }
    }

    return NULL;
}
