#import <Foundation/Foundation.h>

// Runner URLs carry a one-shot callback endpoint. Reports never need a shared
// writable file: the Harness owns the socket and persists the received JSON.
FOUNDATION_EXPORT NSDictionary *SHDWRunnerParameters(NSURL *url);
FOUNDATION_EXPORT BOOL SHDWRunnerSendReport(NSDictionary *report, NSString *callbackURLString);
FOUNDATION_EXPORT BOOL SHDWRunnerFinish(NSString *identifier,
                                          NSString *name,
                                          NSString *version,
                                          NSString *outcome,
                                          NSArray *rounds,
                                          NSDictionary *timing,
                                          NSString *callbackURLString);
