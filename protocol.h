#ifndef shadow_protocol_h
#define shadow_protocol_h

// IPC protocol shared by the vnode client (Shadow.dylib/hooks/vnode.x), the
// Settings bundle (SHDWCapabilities.m) and the daemon (shadowd/main.m).
//
// TRANSPORT: XPC (xpc_connection_create_mach_service on MACH_SERVICE_NAME).
// The original raw mach_msg transport was abandoned because the
// Dopamine-arm64 fork's mach layer is unreliable on some builds (mach_msg
// receive never wakes, MIG calls segfault), while XPC round-trips work
// (libjailbreak's jbdInitPPLRW rides the same machinery).  The wire fields
// are unchanged from the mach protocol, so op/status semantics are
// identical.  Messages are xpc_data blobs containing the structs below,
// stored under the "p" key of an XPC dictionary.
//
// Lease semantics with XPC: the daemon retains the client's CONNECTION as
// the lease; XPC_ERROR_CONNECTION_INVALID on the daemon side replaces the
// mach dead-name notification as owner-death detection.  No client-supplied
// pid — the daemon derives identity from the connection's audit token and
// its own fixed allowlist.

#include <stdint.h>
#include <errno.h>

#define SHADOWD_MAGIC   0x53484457  // 'SHDW'
#define SHADOWD_VERSION 1

// Status codes (errno-style values shared by both sides).
#define SHADOWD_STATUS_OK      0
#define SHADOWD_STATUS_EPERM   EPERM
#define SHADOWD_STATUS_ENOTSUP ENOTSUP
#define SHADOWD_STATUS_EBUSY   EBUSY

typedef enum {
    SHADOWD_OP_PING    = 1,
    SHADOWD_OP_ACQUIRE = 2,
    SHADOWD_OP_RELEASE = 3,
    SHADOWD_OP_STATUS  = 4,  // daemon health: 0 = krw ready, EBUSY = initializing, ENOTSUP = disabled
} shadowd_op_t;

// Client → daemon request payload (xpc_data, key "p").
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t op;
    uint32_t requestId;
} shadowd_xpc_request_t;

// Daemon → client reply payload (xpc_data, key "p").
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t requestId;
    uint32_t status;
} shadowd_xpc_reply_t;

#endif
