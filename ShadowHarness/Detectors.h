#ifndef SHDWDetectors_h
#define SHDWDetectors_h
#import <Foundation/Foundation.h>
FOUNDATION_EXPORT void SHDWRunAllDetectors(void);
FOUNDATION_EXPORT BOOL SHDWRunDetectorWithID(NSString *identifier);
FOUNDATION_EXPORT NSArray<NSString*>* SHDWAllDetectorIDs(void);
#endif
