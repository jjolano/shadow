#ifndef SHDWDetectors_h
#define SHDWDetectors_h
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>

// Per-detector position within an in-progress Run All pass, so the dashboard
// can settle each row the moment its report lands instead of spinning every
// row until the whole pass finishes. Idle when no Run All is active (single
// runs are tracked by the dashboard's own SHDWActiveRuns).
typedef NS_ENUM(NSInteger, SHDWDetectorPassState) {
    SHDWDetectorPassIdle = 0,  // no Run All in progress for this detector
    SHDWDetectorPassPending,   // queued in this pass, not started yet
    SHDWDetectorPassRunning,   // currently executing
    SHDWDetectorPassDone,      // finished this pass (report on disk)
};

FOUNDATION_EXPORT void SHDWRunAllDetectors(void);
FOUNDATION_EXPORT void SHDWRunAllDetectorsWithCompletion(dispatch_block_t completion);
FOUNDATION_EXPORT BOOL SHDWRunDetectorWithID(NSString *identifier);
FOUNDATION_EXPORT NSArray<NSString*>* SHDWAllDetectorIDs(void);
FOUNDATION_EXPORT BOOL SHDWAllDetectorsRunning(void);
FOUNDATION_EXPORT SHDWDetectorPassState SHDWDetectorRunAllState(NSString *identifier);
#endif
