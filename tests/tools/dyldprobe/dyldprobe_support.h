// Query-string helper for dyldprobe's standalone app mode (launchURL /
// openURL handling). The embedded harness path (SHDWDyldProbeWriteDashboard-
// Report) never touches this. Split out of the deleted DetectorRunners/
// RunnerSupport.m, which also carried the TCP transport the runners used.
#import <Foundation/Foundation.h>

static inline NSString *SHDWDyldProbeQueryValue(NSURL *url, NSString *name) {
    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    for (NSURLQueryItem *item in components.queryItems) {
        if ([item.name isEqualToString:name]) return item.value;
    }
    return nil;
}
