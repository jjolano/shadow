//
//  recovery.h
//  shadowd
//
//  Shared crash-recovery decision logic (shadowd/recovery.m), compiled into
//  BOTH the daemon and the host test harness — one source, no copy, no drift
//  guard.  The seams below are provided by each target:
//    - shadowd: allowlisted (main.m) + kptr_plausible, resolve_vnode_for_fd,
//      vnode_set_flag, krw_read32 (krw.m, declared in krw.h)
//    - tests:   ALL of them as configurable test doubles in
//      tests/shadowd/RecoveryHarness.m
//  Each target also provides its own @implementation ShadowResource and the
//  gResources definition.
//

#ifndef shadowd_recovery_h
#define shadowd_recovery_h

#import <Foundation/Foundation.h>

#include "krw.h"   // kptr_plausible, resolve_vnode_for_fd, vnode_set_flag,
                   // krw_read32, vflag_result_t, VISSHADOW + vnode offsets

// Rebuild ONE ledger record (PATH-BASED; runs on the kernel queue after krw
// init).  Appends the surviving record to `kept` (possibly rewritten with a
// fresh vnode) or adopts the resource.
void shdw_recover_one_record(NSString *rec, NSMutableArray<NSString *> *kept);

// Seam functions — exact daemon signatures (allowlisted is main.m-only;
// the rest duplicate krw.h so this header states the whole seam contract).
bool allowlisted(const char *path);
bool kptr_plausible(uint64_t v);
bool resolve_vnode_for_fd(int fd, uint64_t *outVnode, uint64_t *outVId);
vflag_result_t vnode_set_flag(uint64_t vnode, bool set);

// Resource table entry (interface only — each target keeps its own
// @implementation; the shared code uses these exact properties).
@interface ShadowResource : NSObject
@property (nonatomic) int fd;                    // retained fd (>= 0), -1 = restart-adopted
@property (nonatomic) uint64_t vnode;            // resolved vnode
@property (nonatomic) uint64_t vId;              // captured v_id (identity check)
@property (nonatomic) BOOL flagSet;              // VISSHADOW currently set
@property (nonatomic) BOOL verified;             // hide verified by readback (A5)
@property (nonatomic, strong) NSMutableSet<NSString *> *owners;  // owner keys
+ (instancetype)resourceWithFd:(int)fd vnode:(uint64_t)vnode vId:(uint64_t)vId
                       flagSet:(BOOL)flagSet verified:(BOOL)verified owner:(NSString *)ownerKey;
@end

// Resource table (definition provided by each target: main.m, RecoveryHarness.m).
extern NSMutableDictionary<NSString *, ShadowResource *> *gResources;

#endif /* shadowd_recovery_h */