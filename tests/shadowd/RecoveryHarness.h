// Battery interface for the shadowd recovery harness (RecoveryHarness.m).
//
// The harness compiles the REAL recovery decision logic from
// ../shadowd/recovery.m (shared with the daemon — one source, no copy, no
// drift guard) and provides the device seams as configurable test doubles.

#ifndef shadowd_recovery_harness_h
#define shadowd_recovery_harness_h

#import <Foundation/Foundation.h>

// shdw_recover_one_record, ShadowResource @interface, gResources extern,
// seam types (vflag_result_t, VISSHADOW + vnode offsets via krw.h).
#import "../../shadowd/recovery.h"

// Seam configuration.
void shdw_recovery_reset(void);
void shdw_recovery_set_allowlist(NSArray<NSString*>* paths);
void shdw_recovery_set_plausible_range(uint64_t minV, uint64_t maxV);
void shdw_recovery_set_resolve(BOOL ok, uint64_t vnode, uint64_t vId);
void shdw_recovery_set_vflag(vflag_result_t result);
void shdw_recovery_set_krw(BOOL ok, uint64_t vnode, uint32_t flags, uint32_t vId);

#endif