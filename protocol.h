#ifndef shadow_protocol_h
#define shadow_protocol_h

// Mach IPC protocol shared by the vnode client (Shadow.dylib/hooks/vnode.x)
// and the daemon (shadowd/main.m). Raw mach_msg, versioned. The client →
// server request carries a reply port (MACH_MSG_TYPE_MAKE_SEND); the server →
// client reply is a plain message to that port. NO paths, NO client-supplied
// pid — the daemon derives everything from its own fixed allowlist and the
// mach audit trailer.

#include <stdint.h>
#include <mach/message.h>

#define SHADOWD_MAGIC   0x53484457  // 'SHDW'
#define SHADOWD_VERSION 1

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

#endif
