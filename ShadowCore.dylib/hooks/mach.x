#import "hooks.h"

// Single shared bootstrap-service matcher for every bootstrap hook in this
// file and for the sandbox_check mach-lookup denial in sandbox.x (extern
// declared at the top of that file — deliberately NOT in hooks.h). Only
// VERIFIED jailbreak service names/prefixes match; the overbroad "com.ex"
// prefix is gone. The tweak's own "me.jjolano" umbrella is included: a
// detector's lookup of the daemon service is denied, while the tweak's own
// lookups are exempt via isCallerExternal() == NO at each hook site.
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
// unknown-service error. Never fabricates a failure over a real one — the
// callers only reach this after the original SUCCEEDED.
static kern_return_t shdw_bootstrap_hide_right(mach_port_t* sp) {
    if(sp && *sp != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), *sp);
        *sp = MACH_PORT_NULL;
    }

    return BOOTSTRAP_UNKNOWN_SERVICE;
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
    // MACH_SERVICE_NAME ("me.jjolano.shadow.service") falls under the
    // "me.jjolano" blocklist umbrella: detectors' lookups are hidden, while
    // the tweak's own lookups pass (isCallerExternal() == NO) straight
    // through to the original — the vnode client relies on this for its
    // bootstrap_look_up.
    if(!isCallerExternal()) {
        return original_bootstrap_look_up(bp, service_name, sp);
    }

    kern_return_t result = original_bootstrap_look_up(bp, service_name, sp);

    if(result == KERN_SUCCESS && shdw_bootstrap_service_restricted(service_name)) {
        return shdw_bootstrap_hide_right(sp);
    }

    return result;
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

    if(result == KERN_SUCCESS && shdw_bootstrap_service_restricted(service_name)) {
        return shdw_bootstrap_hide_right(sp);
    }

    return result;
}

static kern_return_t (*original_bootstrap_look_up3)(mach_port_t bp, const char* service_name, mach_port_t* sp, pid_t target_pid, uint64_t flags, uint64_t* flags_out);
static kern_return_t replaced_bootstrap_look_up3(mach_port_t bp, const char* service_name, mach_port_t* sp, pid_t target_pid, uint64_t flags, uint64_t* flags_out) {
    if(!isCallerExternal()) {
        return original_bootstrap_look_up3(bp, service_name, sp, target_pid, flags, flags_out);
    }

    kern_return_t result = original_bootstrap_look_up3(bp, service_name, sp, target_pid, flags, flags_out);

    if(result == KERN_SUCCESS && shdw_bootstrap_service_restricted(service_name)) {
        return shdw_bootstrap_hide_right(sp);
    }

    return result;
}

static kern_return_t (*original_bootstrap_look_up_per_user)(mach_port_t bp, const char* service_name, uid_t user_id, mach_port_t* sp);
static kern_return_t replaced_bootstrap_look_up_per_user(mach_port_t bp, const char* service_name, uid_t user_id, mach_port_t* sp) {
    if(!isCallerExternal()) {
        return original_bootstrap_look_up_per_user(bp, service_name, user_id, sp);
    }

    kern_return_t result = original_bootstrap_look_up_per_user(bp, service_name, user_id, sp);

    if(result == KERN_SUCCESS && shdw_bootstrap_service_restricted(service_name)) {
        return shdw_bootstrap_hide_right(sp);
    }

    return result;
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

void shadowhook_mach(HKSubstitutor* hooks) {
    [hooks hookFunction:bootstrap_check_in withReplacement:replaced_bootstrap_check_in outOldPtr:(void **) &original_bootstrap_check_in];
    [hooks hookFunction:bootstrap_look_up withReplacement:replaced_bootstrap_look_up outOldPtr:(void **) &original_bootstrap_look_up];

    // Runtime-resolve the private siblings; skip cleanly when absent.
    void* sym = [hooks findSymbolInImage:NULL symbolName:@"_bootstrap_check_in2"];
    if(sym) [hooks hookFunction:sym withReplacement:replaced_bootstrap_check_in2 outOldPtr:(void **) &original_bootstrap_check_in2];

    sym = [hooks findSymbolInImage:NULL symbolName:@"_bootstrap_check_in3"];
    if(sym) [hooks hookFunction:sym withReplacement:replaced_bootstrap_check_in3 outOldPtr:(void **) &original_bootstrap_check_in3];

    sym = [hooks findSymbolInImage:NULL symbolName:@"_bootstrap_look_up2"];
    if(sym) [hooks hookFunction:sym withReplacement:replaced_bootstrap_look_up2 outOldPtr:(void **) &original_bootstrap_look_up2];

    sym = [hooks findSymbolInImage:NULL symbolName:@"_bootstrap_look_up3"];
    if(sym) [hooks hookFunction:sym withReplacement:replaced_bootstrap_look_up3 outOldPtr:(void **) &original_bootstrap_look_up3];

    sym = [hooks findSymbolInImage:NULL symbolName:@"_bootstrap_look_up_per_user"];
    if(sym) [hooks hookFunction:sym withReplacement:replaced_bootstrap_look_up_per_user outOldPtr:(void **) &original_bootstrap_look_up_per_user];

    sym = [hooks findSymbolInImage:NULL symbolName:@"_pid_for_task"];
    if(sym) [hooks hookFunction:sym withReplacement:replaced_pid_for_task outOldPtr:(void **) &original_pid_for_task];

    sym = [hooks findSymbolInImage:NULL symbolName:@"_mach_port_names"];
    if(sym) [hooks hookFunction:sym withReplacement:replaced_mach_port_names outOldPtr:(void **) &original_mach_port_names];
}
