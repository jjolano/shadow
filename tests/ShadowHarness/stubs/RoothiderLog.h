#import <Foundation/Foundation.h>

// Real Roothider main.m is filtered at fetch time (see build-detector-harness.sh):
// the NSObject category + main() scaffolding are stripped and its NSLog-based
// LOG macro is redirected here so the harness can turn each detect_* function's
// findings into structured checks.
void shdw_roothider_log(NSString *fmt, ...);
#define LOG(...) shdw_roothider_log(@__VA_ARGS__)