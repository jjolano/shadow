// Host test double for shadowd's crash-recovery decision logic.
//
// recover_one_record below is copied VERBATIM from shadowd/main.m — the
// device dependencies (allowlisted, kptr_plausible, resolve_vnode_for_fd,
// vnode_set_flag, krw_read32, gResources, ShadowResource) are replaced by
// configurable seams in this file. The copy is drift-guarded by
// tests/verify-recovery-copy.sh (a body diff against shadowd/main.m) so the
// harness can never silently test stale logic. Any change to the daemon's
// function must be mirrored here.

#import <Foundation/Foundation.h>

#import "RecoveryHarness.h"
#import "../../shadowd/ledger.h"

#import <fcntl.h>
#import <errno.h>
#import <string.h>
#import <unistd.h>

// Device constants (from shadowd/krw.h).
#define VISSHADOW 0x008000
#define OFF_VNODE_V_FLAGS 0x54
#define OFF_VNODE_V_ID 0x74

// vnode flag-outcome type (from shadowd/krw.h) — declared in RecoveryHarness.h.

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

BOOL allowlisted(const char* path) {
    return [gSeamAllowlist containsObject:[NSString stringWithUTF8String:path]];
}

BOOL kptr_plausible(uint64_t v) {
    return v >= gSeamMin && v <= gSeamMax;
}

BOOL resolve_vnode_for_fd(int fd, uint64_t* outVnode, uint64_t* outVId) {
    (void) fd;

    if(!gSeamResolveOK) {
        return NO;
    }

    *outVnode = gSeamFreshVnode;
    *outVId = gSeamFreshVId;
    return YES;
}

vflag_result_t vnode_set_flag(uint64_t vnode, bool set) {
    (void) vnode;
    (void) set;
    return gSeamVFlag;
}

BOOL krw_read32(uint64_t addr, uint32_t* val) {
    if(!gSeamKrwOK || (addr != gSeamKrwVnode + OFF_VNODE_V_ID && addr != gSeamKrwVnode + OFF_VNODE_V_FLAGS)) {
        return NO;
    }

    *val = (addr == gSeamKrwVnode + OFF_VNODE_V_ID) ? gSeamVId : gSeamFlags;
    return YES;
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

// -- the recovery decision logic (VERBATIM from shadowd/main.m) -------------

void shdw_test_recover_one_record(NSString *rec, NSMutableArray<NSString *> *kept) {
    int state = 0;
    NSString *path = nil, *ownerKey = nil;
    uint64_t savedVnode = 0, savedVId = 0;
    if (!ledger_parse_record(rec, &state, &path, &ownerKey, &savedVnode, &savedVId)) {
        return;   // malformed / invalid state / unparseable — logged inside
    }

    if (!allowlisted(path.UTF8String)) {
        shdw_log("ledger: non-allowlisted path dropped: %s", path.UTF8String);
        return;
    }
    // A14: canonical-pointer check BEFORE reading a saved address.
    if (savedVnode == 0 || !kptr_plausible(savedVnode)) {
        shdw_log("ledger: implausible saved vnode dropped: %s", path.UTF8String);
        return;
    }

    ShadowResource *res = gResources[path];
    if (res) {
        [res.owners addObject:ownerKey];
        [kept addObject:rec];
        return;
    }

    int fd = open(path.UTF8String, O_RDONLY);
    if (fd >= 0) {
        // Path currently VISIBLE.
        if (state == 0 /*mayBeHidden*/) {
            // Positive evidence the kernel write never happened (a set
            // flag would make open fail with ENOENT) → the client never
            // got a success reply → safe to roll back; it will retry.
            shdw_log("ledger: mayBeHidden + visible → rolled back: %s", path.UTF8String);
            close(fd);
            return;
        }
        // Record says hidden but the file opens: re-resolve the vnode
        // from the FRESH fd, never trust the saved vnodeAddr.
        uint64_t vnode = 0, vId = 0;
        if (!resolve_vnode_for_fd(fd, &vnode, &vId)) {
            shdw_log("ledger: re-resolve failed for %s", path.UTF8String);
            close(fd);
            [kept addObject:rec];   // keep for a future retry
            return;
        }
        // A10: persist the WAL record with the FRESH vnode BEFORE setting
        // VISSHADOW on it — otherwise a crash between the write and the
        // ledger update leaves the new hidden vnode referenced only by a
        // stale ledger entry.
        if (!ledger_update_record(path.UTF8String, ownerKey.UTF8String, vnode, vId, 1 /*hidden*/)) {
            shdw_log("ledger: WAL update to fresh vnode failed for %s — not hiding", path.UTF8String);
            close(fd);
            [kept addObject:rec];
            return;
        }
        vflag_result_t vr = vnode_set_flag(vnode, true);
        if (vr == VFLAG_FAILED_PRE) {
            shdw_log("ledger: re-hide failed before write for %s", path.UTF8String);
            close(fd);
            [kept addObject:ledger_format_record(1, path.UTF8String, ownerKey.UTF8String, vnode, vId)];
            return;
        }
        gResources[path] = [ShadowResource resourceWithFd:fd vnode:vnode vId:vId flagSet:YES verified:(vr == VFLAG_OK) owner:ownerKey];
        [kept addObject:ledger_format_record(1, path.UTF8String, ownerKey.UTF8String, vnode, vId)];
        if (vr == VFLAG_OK) {
            shdw_log("ledger: re-hidden %s via fresh fd (vnode 0x%llx)", path.UTF8String, vnode);
        } else {
            // A11: write outcome unknown — retain fd + record, adopt as
            // unverified (sweep repairs).
            shdw_log("ledger: re-hide UNVERIFIED for %s — retained fd + record (vnode 0x%llx)", path.UTF8String, vnode);
        }
    } else {
        // A9: ONLY ENOENT is evidence of hiding — EMFILE/EIO/EACCES/...
        // prove nothing, so the record is kept without adopting.
        if (errno != ENOENT) {
            shdw_log("ledger: open(%s) failed with %s — not evidence of hiding, record kept", path.UTF8String, strerror(errno));
            [kept addObject:rec];
            return;
        }
        // ENOENT: the file is genuinely hidden (vnode still flagged) — or
        // it was deleted.  Verify the saved vnode READ-ONLY (flag set +
        // v_id identity) before adopting.
        uint32_t flags = 0, vid = 0;
        if (!krw_read32(savedVnode + OFF_VNODE_V_FLAGS, &flags) || (flags & VISSHADOW) == 0) {
            shdw_log("ledger: saved vnode 0x%llx not flagged — dropped: %s", savedVnode, path.UTF8String);
            return;
        }
        // A14: a saved v_id of 0 cannot be identity-checked — refuse.
        if (savedVId == 0 ||
            (!krw_read32(savedVnode + OFF_VNODE_V_ID, &vid) || vid != (uint32_t)savedVId)) {
            shdw_log("ledger: saved vnode 0x%llx identity mismatch — dropped: %s", savedVnode, path.UTF8String);
            return;
        }
        gResources[path] = [ShadowResource resourceWithFd:-1 vnode:savedVnode vId:savedVId flagSet:YES verified:YES owner:ownerKey];
        [kept addObject:rec];
        shdw_log("ledger: adopted hidden %s (vnode 0x%llx, fd unavailable)", path.UTF8String, savedVnode);
    }
}
