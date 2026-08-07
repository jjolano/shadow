#import "hooks.h"
#import <mach/mach_error.h>
#import <bootstrap.h>

// ---------------------------------------------------------------------------
// Vnode-layer file hiding — thin Mach IPC client.
//
// All kernel-touching work (krw init, vnode lookup/pinning, VISSHADOW, state
// file) lives in the privileged daemon (shadowd, parallel lane). This file is
// the strictly-unprivileged client: it looks up the daemon's Mach service,
// sends an acquire request, and keeps the service-port send right + reply
// port for the process lifetime — the open connection is the ownership lease
// (the daemon watches for our death via the port). The daemon derives the
// hidden paths from its own allowlist; the client sends no paths, no pid,
// and touches no kernel state.
//
// Fail-open by design: any error (lookup failure, timeout, rejection) is
// logged and returns — the app is never blocked and no other hooking is
// affected. Pure userspace IPC: no arch guards, no hook substitution needed.
// ---------------------------------------------------------------------------

#define SHADOWD_MAGIC    0x53484457  // "SHDW"
#define SHADOWD_VERSION  1

enum {
    SHADOWD_OP_ACQUIRE = 1,
    SHADOWD_OP_RELEASE = 2,
    SHADOWD_OP_PING    = 3,
};

// Request payload: {magic, version, op, requestId}. Reply payload: {magic,
// version, requestId, status}. One shared layout keeps the send/receive
// buffer simple (op is client-set, status is daemon-set, both unused halves
// read as zero).
typedef struct {
    mach_msg_header_t header;
    uint32_t magic;
    uint32_t version;
    uint32_t op;
    uint32_t requestId;
    int32_t status;
} shdw_vnode_msg_t;

#define SHADOWD_REPLY_TIMEOUT_MS 2000

// Owner lease: retained for the process lifetime once acquire succeeds.
static mach_port_t shdw_service_port = MACH_PORT_NULL;
static mach_port_t shdw_reply_port = MACH_PORT_NULL;
static uint32_t shdw_request_id = 0;

// Send one request on the retained connection; when waitForReply, block up
// to SHADOWD_REPLY_TIMEOUT_MS for the daemon's reply and validate it.
static kern_return_t
shdw_transact(uint32_t op, BOOL waitForReply, int* status) {
    shdw_vnode_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    uint32_t requestId = ++shdw_request_id;

    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg.header.msgh_remote_port = shdw_service_port;
    msg.header.msgh_local_port = shdw_reply_port;
    msg.header.msgh_voucher_port = MACH_PORT_NULL;
    msg.header.msgh_size = sizeof(msg.header) + 4 * sizeof(uint32_t);  // magic/version/op/requestId

    msg.magic = SHADOWD_MAGIC;
    msg.version = SHADOWD_VERSION;
    msg.op = op;
    msg.requestId = requestId;

    mach_msg_option_t options = MACH_SEND_MSG;
    mach_msg_size_t rcv_size = 0;
    mach_msg_timeout_t timeout = MACH_MSG_TIMEOUT_NONE;

    if(waitForReply) {
        options |= MACH_RCV_MSG | MACH_RCV_TIMEOUT;
        rcv_size = sizeof(msg);
        timeout = SHADOWD_REPLY_TIMEOUT_MS;
    }

    kern_return_t kr = mach_msg(&msg.header, options, msg.header.msgh_size, rcv_size, shdw_reply_port, timeout, MACH_PORT_NULL);
    if(kr != KERN_SUCCESS) {
        return kr;
    }

    if(waitForReply) {
        if(msg.magic != SHADOWD_MAGIC || msg.version != SHADOWD_VERSION || msg.requestId != requestId) {
            NSLog(@"[Shadow] vnode: invalid reply (magic/version/requestId mismatch)");
            return KERN_FAILURE;
        }

        if(status) {
            *status = msg.status;
        }
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
        // (also discards a reply that may still be queued after a timeout).
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

void shadowhook_vnode(HKSubstitutor* hooks) {
    (void) hooks;  // pure IPC client — no hook substitution required

    // One acquire per process (the SpringBoard early path and the app path
    // both reach here; the retained connection is the owner lease).
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
    // death via the service-port send right, so this is courtesy only.
    if(!MACH_PORT_VALID(shdw_service_port)) {
        return;
    }

    int status = 0;
    kern_return_t kr = shdw_transact(SHADOWD_OP_RELEASE, NO, &status);
    if(kr != KERN_SUCCESS) {
        NSLog(@"[Shadow] vnode: release failed: %s", mach_error_string(kr));
    }
}
