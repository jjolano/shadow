// Host test double for shadowd's crash-recovery decision logic.
//
// There is NO copy here: the harness compiles the REAL shadowd/recovery.m
// (../shadowd/recovery.m, shared with the daemon — one source, no drift
// guard).  The device dependencies (allowlisted, kptr_plausible,
// resolve_vnode_for_fd, vnode_set_flag, krw_read32, gResources,
// ShadowResource) are supplied below as configurable seams.

#import <Foundation/Foundation.h>

#import "RecoveryHarness.h"
#import "../../shadowd/recovery.h"
#import "../../shadowd/ledger.h"
#import "../../shadowd/krw.h"

#import <fcntl.h>
#import <errno.h>
#import <string.h>
#import <unistd.h>

// -- configurable seams -----------------------------------------------------

static NSSet<NSString*>* gSeamAllowlist;
static uint64_t gSeamMin = 0, gSeamMax = UINT64_MAX;
static BOOL gSeamResolveOK = NO;
static uint64_t gSeamFreshVnode = 0, gSeamFreshVId = 0;
static vflag_result_t gSeamVFlag = VFLAG_OK;
static BOOL gSeamKrwOK = NO;
static uint64_t gSeamKrwVnode = 0;
static uint32_t gSeamFlags = 0, gSeamVId = 0;

// Exposed to the battery (tests/main.m) via RecoveryHarness.h.
void shdw_recovery_reset(void) {
    gSeamAllowlist = nil;
    gSeamMin = 0;
    gSeamMax = UINT64_MAX;
    gSeamResolveOK = NO;
    gSeamFreshVnode = 0;
    gSeamFreshVId = 0;
    gSeamVFlag = VFLAG_OK;
    gSeamKrwOK = NO;
    gSeamKrwVnode = 0;
    gSeamFlags = 0;
    gSeamVId = 0;
    gResources = [NSMutableDictionary new];
}

void shdw_recovery_set_allowlist(NSArray<NSString*>* paths) {
    gSeamAllowlist = [NSSet setWithArray:paths];
}

void shdw_recovery_set_plausible_range(uint64_t minV, uint64_t maxV) {
    gSeamMin = minV;
    gSeamMax = maxV;
}

void shdw_recovery_set_resolve(BOOL ok, uint64_t vnode, uint64_t vId) {
    gSeamResolveOK = ok;
    gSeamFreshVnode = vnode;
    gSeamFreshVId = vId;
}

void shdw_recovery_set_vflag(vflag_result_t result) {
    gSeamVFlag = result;
}

void shdw_recovery_set_krw(BOOL ok, uint64_t vnode, uint32_t flags, uint32_t vId) {
    gSeamKrwOK = ok;
    gSeamKrwVnode = vnode;
    gSeamFlags = flags;
    gSeamVId = vId;
}

// Seam implementations — signatures must match recovery.h/krw.h exactly
// (bool, not BOOL).
bool allowlisted(const char* path) {
    return [gSeamAllowlist containsObject:[NSString stringWithUTF8String:path]];
}

bool kptr_plausible(uint64_t v) {
    return v >= gSeamMin && v <= gSeamMax;
}

bool resolve_vnode_for_fd(int fd, uint64_t* outVnode, uint64_t* outVId) {
    (void) fd;

    if(!gSeamResolveOK) {
        return false;
    }

    *outVnode = gSeamFreshVnode;
    *outVId = gSeamFreshVId;
    return true;
}

vflag_result_t vnode_set_flag(uint64_t vnode, bool set) {
    (void) vnode;
    (void) set;
    return gSeamVFlag;
}

bool krw_read32(uint64_t addr, uint32_t* val) {
    if(!gSeamKrwOK || (addr != gSeamKrwVnode + OFF_VNODE_V_ID && addr != gSeamKrwVnode + OFF_VNODE_V_FLAGS)) {
        return false;
    }

    *val = (addr == gSeamKrwVnode + OFF_VNODE_V_ID) ? gSeamVId : gSeamFlags;
    return true;
}

// -- ShadowResource + resource table (daemon equivalents) -------------------

@implementation ShadowResource

+ (instancetype)resourceWithFd:(int)fd vnode:(uint64_t)vnode vId:(uint64_t)vId
                       flagSet:(BOOL)flagSet verified:(BOOL)verified owner:(NSString*)ownerKey {
    ShadowResource* nr = [ShadowResource new];
    nr.fd = fd;
    nr.vnode = vnode;
    nr.vId = vId;
    nr.flagSet = flagSet;
    nr.verified = verified;
    nr.owners = [NSMutableSet setWithObject:ownerKey];
    return nr;
}

@end

NSMutableDictionary<NSString*, ShadowResource*>* gResources;