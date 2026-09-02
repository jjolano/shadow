#ifndef SHDWDetectors_h
#define SHDWDetectors_h
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
FOUNDATION_EXPORT void SHDWRunAllDetectors(void);
FOUNDATION_EXPORT void SHDWRunAllDetectorsWithCompletion(dispatch_block_t completion);
FOUNDATION_EXPORT BOOL SHDWRunDetectorWithID(NSString *identifier);
FOUNDATION_EXPORT NSArray<NSString*>* SHDWAllDetectorIDs(void);
FOUNDATION_EXPORT BOOL SHDWAllDetectorsRunning(void);
#endif
