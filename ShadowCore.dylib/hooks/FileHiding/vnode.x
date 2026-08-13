#import "hooks.h"
#import <mach/mach.h>
#import <xpc/xpc.h>

#import "../../protocol.h"

#import <Shadow/JBPath.h>
// Vnode-layer file hiding — thin IPC client. All kernel-touching work
// (krw init, vnode pinning, VISSHADOW, state file) lives in the privileged
// daemon (shadowd); this strictly-unprivileged client sends acquire/release
// over the daemon's XPC mach service. The daemon derives hidden paths from
// its own allowlist — the client sends no paths, no pid, touches no kernel
// state. The daemon keeps the client's XPC connection as the lease: it dies
// with us (XPC_ERROR_CONNECTION_INVALID on the daemon side), no client-side
// cleanup needed. Fail-open: any error logs and returns; the app is never
// blocked, no hooking is affected. Pure userspace IPC: no arch guards, no
// hook substitution needed.

// Protocol (protocol.h, shared with shadowd/main.m): XPC mach-service
// connection; payloads are xpc_data blobs of shadowd_xpc_request_t /
// shadowd_xpc_reply_t. Status is an errno value (0 ok | EPERM | ENOTSUP |
// EBUSY).  The raw mach_msg transport was abandoned because the
// Dopamine-arm64 fork's mach layer is unreliable on some builds; XPC
// round-trips work.
#define SHADOWD_REPLY_TIMEOUT_MS 2000

// Kept for the process lifetime once acquire succeeds: the XPC connection
// (the daemon's lease).
static xpc_connection_t shdw_xpc_conn = NULL;
static uint32_t shdw_request_id = 0;
// Reply status written by the reply block; static so a reply arriving after
// a timeout cannot write into the caller's (already returned) stack frame.
static int gShdwReplyStatus = 0;

static void shdw_xpc_disconnect(void) {
    if (shdw_xpc_conn) {
        xpc_connection_cancel(shdw_xpc_conn);   // ARC releases on NULL
        shdw_xpc_conn = NULL;
    }
}

// Send one request on the retained connection; when waitForReply, block up
// to SHADOWD_REPLY_TIMEOUT_MS for the daemon's reply and validate it.
static kern_return_t
shdw_xpc_transact(uint32_t op, BOOL waitForReply, int* status) {
    if (!shdw_xpc_conn) {
        shdw_xpc_conn = xpc_connection_create_mach_service(MACH_SERVICE_NAME, NULL, 0);
        if (!shdw_xpc_conn) {
            NSLog(@"[Shadow] vnode: xpc connection creation failed");
            return KERN_FAILURE;
        }
        xpc_connection_set_event_handler(shdw_xpc_conn, ^(xpc_object_t obj) {
            if (obj == XPC_ERROR_CONNECTION_INVALID) {
                NSLog(@"[Shadow] vnode: connection invalidated");
            }
        });
        xpc_connection_resume(shdw_xpc_conn);
    }

    shadowd_xpc_request_t req;
    memset(&req, 0, sizeof(req));
    req.magic = SHADOWD_MAGIC;
    req.version = SHADOWD_VERSION;
    req.op = op;
    req.requestId = ++shdw_request_id;

    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_data(msg, "p", &req, sizeof(req));

    if (!waitForReply) {
        xpc_connection_send_message(shdw_xpc_conn, msg);
        return KERN_SUCCESS;
    }

    __block kern_return_t result = KERN_SUCCESS;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    xpc_connection_send_message_with_reply(shdw_xpc_conn, msg, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^(xpc_object_t reply) {
        if (xpc_get_type(reply) == XPC_TYPE_ERROR) {
            NSLog(@"[Shadow] vnode: xpc reply error");
            result = KERN_FAILURE;
        } else {
            size_t len = 0;
            const void *data = xpc_dictionary_get_data(reply, "p", &len);
            if (len == sizeof(shadowd_xpc_reply_t)) {
                const shadowd_xpc_reply_t *r = (const shadowd_xpc_reply_t *)data;
                if (r->magic == SHADOWD_MAGIC && r->version == SHADOWD_VERSION && r->requestId == req.requestId) {
                    gShdwReplyStatus = (int)r->status;
                    dispatch_semaphore_signal(sem);
                    return;
                }
            }
            NSLog(@"[Shadow] vnode: invalid reply (magic/version/requestId mismatch)");
            result = KERN_FAILURE;
        }
        dispatch_semaphore_signal(sem);
    });

    if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, SHADOWD_REPLY_TIMEOUT_MS * NSEC_PER_MSEC)) != 0) {
        NSLog(@"[Shadow] vnode: %s timed out (fail open)", op == SHADOWD_OP_ACQUIRE ? "acquire" : "request");
        return KERN_FAILURE;
    }
    if (status) {
        *status = gShdwReplyStatus;
    }
    return result;
}

// Connect to the daemon, send acquire, wait for the reply.  On success the
// connection is retained as the lease; on any failure everything is torn
// down and the error returned (fail open).
static kern_return_t
shdw_acquire(void) {
    int status = 0;
    kern_return_t kr = shdw_xpc_transact(SHADOWD_OP_ACQUIRE, YES, &status);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[Shadow] vnode: acquire failed");
        shdw_xpc_disconnect();
        return kr;
    }

    if (status != 0) {
        // Daemon rejected the acquire (e.g. ENOTSUP): fail open, no lease.
        NSLog(@"[Shadow] vnode: daemon rejected acquire (status %d)", status);
        shdw_xpc_disconnect();
        return KERN_FAILURE;
    }

    NSLog(@"[Shadow] vnode: acquired (status %d)", status);
    return KERN_SUCCESS;
}

// Feature gate: "VnodeHiding" in Shadow's prefs plist (default OFF).
// SHADOW_PREFS_PLIST tracks the bundle
// id (me.jjolano.shadow); on rootless the plist lives under /var/jb, so try
// both paths. The pref is read ONCE (dispatch_once); the detector escalation
// is re-evaluated per call so a detection library that loads after the first
// evaluation still triggers acquisition.
//
// B2c: the resolved effective preference now arrives from dylib.x (the ctor
// already holds prefs_load — a second independent plist read was the drift
// the lifecycle rewrite targets). shdw_vnode_set_pref_enabled: stores the
// caller-resolved value; shdw_vnode_pref_enabled: returns it when set, and
// falls back to this file's own plist read ONLY for call sites that cannot
// reach a resolved pref (the detector-escalation re-arm in
// shdw_detector_detected has no prefs_load in scope). The two resolutions
// are behaviorally identical (both apply per-app override → global →
// default NO), so the fallback never changes the gate.
static BOOL shdw_vnode_pref_resolved = NO;
static BOOL shdw_vnode_pref_has_resolved = NO;   // setter called

void shdw_vnode_set_pref_enabled(BOOL enabled) {
    shdw_vnode_pref_resolved = enabled;
    shdw_vnode_pref_has_resolved = YES;
}

static BOOL shdw_vnode_pref_enabled(void) {
    if(shdw_vnode_pref_has_resolved) {
        return shdw_vnode_pref_resolved;
    }

    static BOOL enabled = NO;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSDictionary* prefs = nil;

        for(NSString* path in @[
            JBPath(@(SHADOW_PREFS_PLIST)),
            @(SHADOW_PREFS_PLIST)
        ]) {
            prefs = [NSDictionary dictionaryWithContentsOfFile:path];

            if(prefs) {
                break;
            }
        }

        if(!prefs) {
            return;
        }

        // Per-app dict (when the app is enabled there) overrides the global key.
        NSString* bundleIdentifier = [Shadow getBundleIdentifier];

        if(bundleIdentifier) {
            NSDictionary* appPrefs = prefs[bundleIdentifier];

            if([appPrefs isKindOfClass:[NSDictionary class]] && [appPrefs[@"App_Enabled"] boolValue]) {
                // Per-app value wins; a key the app doesn't set inherits the
                // global (matches the Settings UI and
                // getPreferencesForIdentifier: — a bare per-app dict must not
                // silently force the flag off).
                id value = appPrefs[@"VnodeHiding"];

                if(value) {
                    enabled = [value boolValue];
                    return;
                }
            }
        }

        enabled = [prefs[@"VnodeHiding"] boolValue];
    });

    return enabled;
}

// Re-evaluated on every call: shdw_detector_present flips via
// shdw_detector_detected when a detection library is found post-spawn, so a
// gate evaluated OFF at ctor time is revisited when the detector arrives.
static BOOL shdw_vnode_hiding_enabled(void) {
    return shdw_detector_present || shdw_vnode_pref_enabled();
}

void shadowhook_vnode(HKSubstitutor* hooks) {
    (void) hooks;  // pure IPC client — no hook substitution required

    // Gate first, re-evaluable: a late detector must still reach the acquire
    // below (shdw_detector_detected re-invokes this entry).
    if(!shdw_vnode_hiding_enabled()) {
        NSLog(@"[Shadow] vnode: hiding disabled, skipping acquire");
        return;
    }

    // One acquire per process (the once guard). The retained connection is
    // the owner lease.
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        kern_return_t kr = shdw_acquire();

        // Connection interruption (daemon may have restarted): one reconnect
        // attempt with a fresh connection. Never loop.
        if(kr != KERN_SUCCESS) {
            NSLog(@"[Shadow] vnode: retrying acquire once");
            shdw_acquire();
        }
    });
}

void shadowhook_vnode_release(void) {
    // Best-effort, no wait: used at deinit. The daemon also notices our
    // death via the connection invalidation, so this is courtesy only.
    if(!shdw_xpc_conn) {
        return;
    }

    int status = 0;
    kern_return_t kr = shdw_xpc_transact(SHADOWD_OP_RELEASE, NO, &status);
    if(kr != KERN_SUCCESS) {
        NSLog(@"[Shadow] vnode: release failed");
    }
}
