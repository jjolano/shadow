// Battery interface for the shadowd recovery harness (RecoveryHarness.m).

#ifndef shadowd_recovery_harness_h
#define shadowd_recovery_harness_h

#import <Foundation/Foundation.h>

// The verbatim recovery decision logic (drift-guarded against shadowd/main.m).
void shdw_test_recover_one_record(NSString* rec, NSMutableArray<NSString*>* kept);

// VISSHADOW flag bit (from shadowd/krw.h) — needed to drive the krw seam.
#define VISSHADOW 0x008000

// vnode flag-outcome type (from shadowd/krw.h).
typedef enum {
    VFLAG_OK = 0,
    VFLAG_FAILED_PRE,
    VFLAG_MAYBE,
} vflag_result_t;

// Seam configuration.
void shdw_recovery_reset(void);
void shdw_recovery_set_allowlist(NSArray<NSString*>* paths);
void shdw_recovery_set_plausible_range(uint64_t minV, uint64_t maxV);
void shdw_recovery_set_resolve(BOOL ok, uint64_t vnode, uint64_t vId);
void shdw_recovery_set_vflag(vflag_result_t result);
void shdw_recovery_set_krw(BOOL ok, uint64_t vnode, uint32_t flags, uint32_t vId);

// The resource table (seam global).
@interface ShadowResource : NSObject
@property (nonatomic) int fd;
@property (nonatomic) uint64_t vnode;
@property (nonatomic) uint64_t vId;
@property (nonatomic) BOOL flagSet;
@property (nonatomic) BOOL verified;
@property (nonatomic, strong) NSMutableSet<NSString*>* owners;
+ (instancetype)resourceWithFd:(int)fd vnode:(uint64_t)vnode vId:(uint64_t)vId
                       flagSet:(BOOL)flagSet verified:(BOOL)verified owner:(NSString*)ownerKey;
@end

extern NSMutableDictionary<NSString*, ShadowResource*>* gResources;

#endif
