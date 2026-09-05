#import "UniversalHooks.h"
#import <xpc/xpc.h>

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

// Fast-path for an external lookup of a restricted name: a sandboxed stock app
// is denied these before any IPC leaves the process, so return
// BOOTSTRAP_NOT_PRIVILEGED WITHOUT calling the original. Besides concealing the
// right, this removes a timing side-channel — a probe that times a restricted
// prefix (cy:/lh:) against a plain name (detect_launchd_ipchook) would see the
// hooked path run the real launchd round-trip PLUS our work and flag the added
// latency; short-circuiting makes the concealed lookup FASTER than the control,
// and the probe only flags slower results. Returns YES if it handled the call.
static BOOL shdw_bootstrap_shortcircuit_restricted(const char* service_name, mach_port_t* sp, kern_return_t* out) {
    if(!shdw_bootstrap_service_restricted(service_name)) {
        return NO;
    }
    if(sp) *sp = MACH_PORT_NULL;
    *out = BOOTSTRAP_NOT_PRIVILEGED;
    return YES;
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

    kern_return_t shortcircuit;
    if(shdw_bootstrap_shortcircuit_restricted(service_name, sp, &shortcircuit)) {
        return shortcircuit;
    }

    return original_bootstrap_look_up(bp, service_name, sp);
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

// mach_port_names: pass-through.
static kern_return_t (*original_mach_port_names)(ipc_space_t task, mach_port_name_array_t* names, mach_msg_type_number_t* namesCnt, mach_port_type_array_t* types, mach_msg_type_number_t* typesCnt);
static kern_return_t replaced_mach_port_names(ipc_space_t task, mach_port_name_array_t* names, mach_msg_type_number_t* namesCnt, mach_port_type_array_t* types, mach_msg_type_number_t* typesCnt) {
    return original_mach_port_names(task, names, namesCnt, types, typesCnt);
}

// --- launchd XPC probes ---
// Neutralise patched-launchd replies for external callers. Internal callers
// pass through untouched.

// libxpc private entry points (declared here; not in the public SDK headers).
// Use the SDK's xpc_object_t (an ObjC bridged type) to match the existing
// declarations of the xpc_dictionary_* accessors from <xpc/xpc.h>.
extern int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t request, xpc_object_t* reply);
extern int xpc_pipe_routine_with_flags(xpc_object_t pipe, xpc_object_t request, xpc_object_t* reply, uint32_t flags);

// Returns YES if the request is one of the two jailbreak-only launchd routines,
// and reports which via *isDeplatformized.
static BOOL shdw_xpc_request_is_jb(xpc_object_t request, BOOL* isDeplatformized) {
    if(isDeplatformized) *isDeplatformized = NO;
    if(!request) return NO;

    if(xpc_dictionary_get_uint64(request, "jb-domain") != 0) {
        return YES;
    }
    if(xpc_dictionary_get_uint64(request, "subsystem") == 3 &&
       xpc_dictionary_get_uint64(request, "routine") == 815) {
        if(isDeplatformized) *isDeplatformized = YES;
        return YES;
    }
    return NO;
}

// The stock launchd answer for each probe:
//  - jb-server (jb-domain): a stock launchd has no jailbreak-server routine, so
//    the call fails. detect_launchd_jbserver returns early on any non-zero
//    result and only reports when the call SUCCEEDS with a reply, so return a
//    non-zero error and no reply — the probe then sees nothing.
//  - deplatformized (routine 815): stock launchd rejects it with error 154,
//    which the probe treats as the clean outcome. Return 154 with an
//    { error: 154 } reply so either check path (rc==154 or reply error==154)
//    reads as stock.
#define SHDW_XPC_STOCK_JB_ERR      1     // any non-zero: "routine unavailable"
#define SHDW_XPC_DEPLATFORM_ERR    154

static xpc_object_t shdw_xpc_deplatform_reply(void) {
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    if(dict) {
        xpc_dictionary_set_int64(dict, "error", SHDW_XPC_DEPLATFORM_ERR);
    }
    return dict;
}

// Shared handler for both pipe-routine variants: returns YES and sets *outRC if
// the request is a jailbreak probe that must be answered with a stock result.
static BOOL shdw_xpc_neutralize(xpc_object_t request, xpc_object_t* reply, int* outRC) {
    BOOL deplatform = NO;
    if(!shdw_xpc_request_is_jb(request, &deplatform)) {
        return NO;
    }
    if(deplatform) {
        if(reply) *reply = shdw_xpc_deplatform_reply();
        *outRC = SHDW_XPC_DEPLATFORM_ERR;
    } else {
        if(reply) *reply = NULL;
        *outRC = SHDW_XPC_STOCK_JB_ERR;
    }
    return YES;
}

static int (*original_xpc_pipe_routine)(xpc_object_t pipe, xpc_object_t request, xpc_object_t* reply);
static int replaced_xpc_pipe_routine(xpc_object_t pipe, xpc_object_t request, xpc_object_t* reply) {
    if(isCallerExternal()) {
        int rc = 0;
        if(shdw_xpc_neutralize(request, reply, &rc)) {
            return rc;
        }
    }
    return original_xpc_pipe_routine(pipe, request, reply);
}

static int (*original_xpc_pipe_routine_with_flags)(xpc_object_t pipe, xpc_object_t request, xpc_object_t* reply, uint32_t flags);
static int replaced_xpc_pipe_routine_with_flags(xpc_object_t pipe, xpc_object_t request, xpc_object_t* reply, uint32_t flags) {
    if(isCallerExternal()) {
        int rc = 0;
        if(shdw_xpc_neutralize(request, reply, &rc)) {
            return rc;
        }
    }
    return original_xpc_pipe_routine_with_flags(pipe, request, reply, flags);
}

// --- launchd jailbreak Mach-server probe (Dopamine "DOPAMINE" magic) ---
//
// detect_launchd_jb_mach_server hand-rolls a Mach message to launchd carrying
// the magic 0x444F50414D494E45 ("DOPAMINE") and msgh_id 0x40000000|206, then a
// paired MACH_RCV for the reply. On a device WITHOUT Dopamine's launchd patch
// the send fails (MACH_SEND_INVALID_DEST) — but the probe LOGS that failure as
// a finding, so it fires on a stock device too (a self-inflicted false
// positive). To present the clean outcome, intercept the magic exchange: drop
// the real send (return success) and synthesize the paired receive as a reply
// whose status is non-zero, so neither of the probe's log branches
// (send-error, or status==0 with a jbRootPath) triggers.
//
// Scope is tight: only a MACH_SEND whose body carries the exact magic is
// touched, and only for external callers; every other mach_msg passes straight
// through. A thread-local flag pairs the dropped send with the next receive on
// the same thread (the probe issues them back-to-back).
#define SHDW_JBSERVER_MACH_MAGIC 0x444F50414D494E45ULL

static _Thread_local BOOL shdw_jbserver_send_pending = NO;

static mach_msg_return_t (*original_mach_msg)(mach_msg_header_t*, mach_msg_option_t,
    mach_msg_size_t, mach_msg_size_t, mach_port_name_t, mach_msg_timeout_t, mach_port_name_t);

// The message layout the probe uses: header, then two uint64 (magic, action).
typedef struct {
    mach_msg_header_t hdr;
    uint64_t magic;
    uint64_t action;
} shdw_jbserver_msg_t;

static mach_msg_return_t replaced_mach_msg(mach_msg_header_t* msg, mach_msg_option_t option,
    mach_msg_size_t sendSize, mach_msg_size_t receiveLimit, mach_port_name_t receiveName,
    mach_msg_timeout_t timeout, mach_port_name_t notify) {

    if(isCallerExternal() && msg) {
        // Outbound magic message → drop the send, arm the paired receive.
        if((option & MACH_SEND_MSG) && sendSize >= sizeof(shdw_jbserver_msg_t) &&
           ((const shdw_jbserver_msg_t*)msg)->magic == SHDW_JBSERVER_MACH_MAGIC) {
            shdw_jbserver_send_pending = YES;
            return MACH_MSG_SUCCESS;   // pretend the send succeeded
        }
        // The receive that the probe issues right after the magic send: return a
        // minimal successful reply with a non-zero status word. The probe's
        // reply layout is { {hdr, magic, action}, status, … }; status sits
        // immediately after the 8-byte magic + 8-byte action following the
        // header. Setting it non-zero makes the probe treat the server as
        // "present but not a jailbreak" and log nothing.
        if((option & MACH_RCV_MSG) && shdw_jbserver_send_pending) {
            shdw_jbserver_send_pending = NO;
            if(receiveLimit >= sizeof(shdw_jbserver_msg_t) + sizeof(uint64_t)) {
                shdw_jbserver_msg_t* base = (shdw_jbserver_msg_t*) msg;
                base->hdr.msgh_bits = 0;
                base->hdr.msgh_size = sizeof(shdw_jbserver_msg_t) + sizeof(uint64_t);
                base->hdr.msgh_remote_port = MACH_PORT_NULL;
                base->hdr.msgh_local_port = MACH_PORT_NULL;
                base->magic = SHDW_JBSERVER_MACH_MAGIC;
                base->action = 0;
                *(uint64_t*)((uint8_t*)msg + sizeof(shdw_jbserver_msg_t)) = (uint64_t)-1; // status != 0
                return MACH_MSG_SUCCESS;
            }
            return MACH_RCV_TOO_LARGE;
        }
    }

    return original_mach_msg(msg, option, sendSize, receiveLimit, receiveName, timeout, notify);
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

    // Private libxpc bootstrap siblings. The public bootstrap_look_up/check_in
    // above route through these internally, and an entry patch on the resolved
    // libxpc address catches those internal calls. But a detector can also call
    // a sibling DIRECTLY through its own import stub — the re-exported-symbol
    // path where an entry patch silently no-ops (see the rebind rationale
    // above). Try the entry patch first (covers internal/direct-branch callers
    // and captures the true original); only if it is refused fall back to an
    // import-slot rebind, exactly as the mach_msg hook does. Skipped cleanly if
    // the symbol is absent.
    // dlsym name carries the leading underscore (`_bootstrap_look_up2`); the
    // rebind lane matches the C name without it (`bootstrap_look_up2`).
    #define SHDW_HOOK_BOOTSTRAP_SIBLING(dlname, rebindname, repl, orig)          \
        do {                                                                     \
            void* _s = shdw_resolve_libsystem(dlname);                           \
            if(_s && ![hooks hookFunction:_s withReplacement:(void*)(repl)      \
                                 outOldPtr:(void**)&(orig)]) {                    \
                [hooks hookRebindSymbol:@rebindname withReplacement:(void*)(repl) \
                              outOldPtr:(void**)&(orig)];                        \
            }                                                                    \
        } while(0)
    SHDW_HOOK_BOOTSTRAP_SIBLING("_bootstrap_check_in2", "bootstrap_check_in2", replaced_bootstrap_check_in2, original_bootstrap_check_in2);
    SHDW_HOOK_BOOTSTRAP_SIBLING("_bootstrap_check_in3", "bootstrap_check_in3", replaced_bootstrap_check_in3, original_bootstrap_check_in3);
    SHDW_HOOK_BOOTSTRAP_SIBLING("_bootstrap_look_up2", "bootstrap_look_up2", replaced_bootstrap_look_up2, original_bootstrap_look_up2);
    SHDW_HOOK_BOOTSTRAP_SIBLING("_bootstrap_look_up3", "bootstrap_look_up3", replaced_bootstrap_look_up3, original_bootstrap_look_up3);
    SHDW_HOOK_BOOTSTRAP_SIBLING("_bootstrap_look_up_per_user", "bootstrap_look_up_per_user", replaced_bootstrap_look_up_per_user, original_bootstrap_look_up_per_user);
    #undef SHDW_HOOK_BOOTSTRAP_SIBLING
    void* sym = NULL; (void)sym;

    sym = shdw_resolve_libsystem("_pid_for_task");
    if(sym) [hooks hookFunction:sym withReplacement:replaced_pid_for_task outOldPtr:(void **) &original_pid_for_task];

    sym = shdw_resolve_libsystem("_mach_port_names");
    if(sym) [hooks hookFunction:sym withReplacement:replaced_mach_port_names outOldPtr:(void **) &original_mach_port_names];

    // launchd XPC jailbreak-probe neutralizers. Rebind through the import-slot
    // lane (same reason as bootstrap_look_up: these are libxpc re-exports an
    // entry patch can miss). Skipped cleanly if the symbols are absent.
    [hooks hookRebindSymbol:@"xpc_pipe_routine" withReplacement:(void*)replaced_xpc_pipe_routine outOldPtr:(void **) &original_xpc_pipe_routine];
    [hooks hookRebindSymbol:@"xpc_pipe_routine_with_flags" withReplacement:(void*)replaced_xpc_pipe_routine_with_flags outOldPtr:(void **) &original_xpc_pipe_routine_with_flags];

    // launchd jailbreak Mach-server probe: intercept only the DOPAMINE-magic
    // exchange (see replaced_mach_msg). Rebind the import slot so the probe's
    // own mach_msg call routes through us; mach_msg is a shared-cache re-export
    // an entry patch can miss.
    [hooks hookRebindSymbol:@"mach_msg" withReplacement:(void*)replaced_mach_msg outOldPtr:(void **) &original_mach_msg];
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
