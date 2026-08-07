#import "hooks.h"
#import <mach/mach_error.h>
#import <bootstrap.h>
#import <RootBridge.h>

// Vnode-layer file hiding — thin Mach IPC client. All kernel-touching work
// (krw init, vnode pinning, VISSHADOW, state file) lives in the privileged
// daemon (shadowd); this strictly-unprivileged client sends acquire/release
// over the daemon's Mach service. The daemon derives hidden paths from its
// own allowlist — the client sends no paths, no pid, touches no kernel
// state. The daemon keeps a send right to our reply port and arms a
// dead-name notification on it: the lease dies with us, no client-side
// cleanup needed. Fail-open: any error logs and returns; the app is never
// blocked, no hooking is affected. Pure userspace IPC: no arch guards, no
// hook substitution needed.

// Protocol (shadowd/main.m verbatim): request is a complex message carrying
// the reply port as a MACH_MSG_TYPE_MAKE_SEND descriptor; reply is a plain
// message. Status is an errno value (0 ok | EPERM | ENOTSUP | EBUSY).
#define SHADOWD_MAGIC    0x53484457  // 'SHDW'
#define SHADOWD_VERSION  1

typedef enum {
    SHADOWD_OP_PING    = 1,
    SHADOWD_OP_ACQUIRE = 2,
    SHADOWD_OP_RELEASE = 3,
} shadowd_op_t;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t replyPort;   // MACH_MSG_TYPE_MAKE_SEND
    uint32_t magic;
    uint32_t version;
    uint32_t op;
    uint32_t requestId;
} shadowd_request_t;

typedef struct {
    mach_msg_header_t header;
    uint32_t magic;
    uint32_t version;
    uint32_t requestId;
    uint32_t status;
} shadowd_reply_t;

#define SHADOWD_REPLY_TIMEOUT_MS 2000

// Kept for the process lifetime once acquire succeeds: the service-port send
// right (our connection) and the reply-port receive right (the daemon's
// lease is a send right to it, dead-name notified on our death).
static mach_port_t shdw_service_port = MACH_PORT_NULL;
static mach_port_t shdw_reply_port = MACH_PORT_NULL;
static uint32_t shdw_request_id = 0;

// Send one request on the retained connection; when waitForReply, block up to
// SHADOWD_REPLY_TIMEOUT_MS for the daemon's reply and validate it.
static kern_return_t
shdw_transact(uint32_t op, BOOL waitForReply, int* status) {
    shadowd_request_t req;
    memset(&req, 0, sizeof(req));

    uint32_t requestId = ++shdw_request_id;

    req.header.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    req.header.msgh_remote_port = shdw_service_port;
    req.header.msgh_local_port = MACH_PORT_NULL;
    req.header.msgh_voucher_port = MACH_PORT_NULL;
    req.header.msgh_size = sizeof(req);

    req.msgh_body.msgh_descriptor_count = 1;
    req.replyPort.name = shdw_reply_port;
    req.replyPort.disposition = MACH_MSG_TYPE_MAKE_SEND;
    req.replyPort.type = MACH_MSG_PORT_DESCRIPTOR;

    req.magic = SHADOWD_MAGIC;
    req.version = SHADOWD_VERSION;
    req.op = op;
    req.requestId = requestId;

    kern_return_t kr = mach_msg(&req.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof(req), 0, MACH_PORT_NULL, SHADOWD_REPLY_TIMEOUT_MS, MACH_PORT_NULL);
    if(kr != KERN_SUCCESS) {
        return kr;
    }

    if(!waitForReply) {
        return KERN_SUCCESS;
    }

    // Reply buffer: message size + the kernel-appended trailer
    // (MAX_TRAILER_SIZE). An undersized rcv_size makes mach_msg return
    // MACH_RCV_TOO_LARGE and the reply is never delivered — the acquire
    // would silently never succeed.
    union {
        shadowd_reply_t reply;
        uint8_t buf[sizeof(shadowd_reply_t) + MAX_TRAILER_SIZE];
    } replyBuf;
    memset(&replyBuf, 0, sizeof(replyBuf));
    kr = mach_msg(&replyBuf.reply.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(replyBuf.buf), shdw_reply_port, SHADOWD_REPLY_TIMEOUT_MS, MACH_PORT_NULL);
    if(kr != KERN_SUCCESS) {
        return kr;
    }

    // The daemon replies with a COPY_SEND of the reply-port send right it
    // holds — drop our copy so it doesn't leak per transaction.
    if(MACH_PORT_VALID(replyBuf.reply.header.msgh_remote_port)) {
        mach_port_deallocate(mach_task_self(), replyBuf.reply.header.msgh_remote_port);
    }

    if(replyBuf.reply.magic != SHADOWD_MAGIC || replyBuf.reply.version != SHADOWD_VERSION || replyBuf.reply.requestId != requestId) {
        NSLog(@"[Shadow] vnode: invalid reply (magic/version/requestId mismatch)");
        return KERN_FAILURE;
    }

    if(status) {
        *status = (int)replyBuf.reply.status;
    }

    return KERN_SUCCESS;
}

// Look up the daemon, allocate the reply port, send acquire, wait for the
// reply. On success the connection (service port + reply port) is retained
// as the lease; on any failure everything is torn down and the error
// returned (fail open).
static kern_return_t
shdw_acquire(void) {
    kern_return_t kr = bootstrap_look_up(bootstrap_port, MACH_SERVICE_NAME, &shdw_service_port);

    if(kr != KERN_SUCCESS || !MACH_PORT_VALID(shdw_service_port)) {
        NSLog(@"[Shadow] vnode: bootstrap_look_up(%s) failed: %s", MACH_SERVICE_NAME, mach_error_string(kr));
        shdw_service_port = MACH_PORT_NULL;
        return kr ? kr : KERN_FAILURE;
    }

    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &shdw_reply_port);
    if(kr != KERN_SUCCESS) {
        NSLog(@"[Shadow] vnode: reply port allocation failed: %s", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), shdw_service_port);
        shdw_service_port = MACH_PORT_NULL;
        return kr;
    }

    int status = 0;
    kr = shdw_transact(SHADOWD_OP_ACQUIRE, YES, &status);
    if(kr != KERN_SUCCESS) {
        NSLog(@"[Shadow] vnode: acquire failed: %s", mach_error_string(kr));
        // mach_port_destruct: non-deprecated equivalent of mach_port_destroy
        // (also discards a reply still queued after a timeout).
        mach_port_destruct(mach_task_self(), shdw_reply_port, 0, 0);
        mach_port_deallocate(mach_task_self(), shdw_service_port);
        shdw_reply_port = MACH_PORT_NULL;
        shdw_service_port = MACH_PORT_NULL;
        return kr;
    }

    if(status != 0) {
        // Daemon rejected the acquire (e.g. ENOTSUP): fail open, no lease.
        NSLog(@"[Shadow] vnode: daemon rejected acquire (status %d)", status);
        mach_port_destruct(mach_task_self(), shdw_reply_port, 0, 0);
        mach_port_deallocate(mach_task_self(), shdw_service_port);
        shdw_reply_port = MACH_PORT_NULL;
        shdw_service_port = MACH_PORT_NULL;
        return KERN_FAILURE;
    }

    NSLog(@"[Shadow] vnode: acquired (status %d)", status);
    return KERN_SUCCESS;
}

// Feature gate: "VnodeHiding" in Shadow's prefs plist (default OFF) — same
// pattern as dyld.x's MemoryLevelHiding. SHADOW_PREFS_PLIST tracks the bundle
// id (me.jjolano.shadow); on rootless the plist lives under /var/jb, so try
// both paths. The pref is read ONCE (dispatch_once); the detector escalation
// is re-evaluated per call so a detection library that loads after the first
// evaluation still triggers acquisition.
static BOOL shdw_vnode_pref_enabled(void) {
    static BOOL enabled = NO;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSDictionary* prefs = nil;

        for(NSString* path in @[
            [RootBridge getJBPath:@(SHADOW_PREFS_PLIST)],
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
        // attempt with a fresh lookup. Never loop. A failed lookup means the
        // service isn't registered at all — nothing to reconnect to.
        if(kr != KERN_SUCCESS && kr != BOOTSTRAP_UNKNOWN_SERVICE) {
            NSLog(@"[Shadow] vnode: retrying acquire once");
            shdw_acquire();
        }
    });
}

void shadowhook_vnode_release(void) {
    // Best-effort, no wait: used at deinit. The daemon also notices our
    // death via its dead-name notification on the reply port, so this is
    // courtesy only.
    if(!MACH_PORT_VALID(shdw_service_port)) {
        return;
    }

    int status = 0;
    kern_return_t kr = shdw_transact(SHADOWD_OP_RELEASE, NO, &status);
    if(kr != KERN_SUCCESS) {
        NSLog(@"[Shadow] vnode: release failed: %s", mach_error_string(kr));
    }
}
