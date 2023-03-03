#import "HKSubstrate.h"
#import <HookKit/Core.h>

__attribute__ ((constructor)) static void module_init(void) {
    HKSubstrate* module = [HKSubstrate new];
    [module setNullImageSearchSupported:YES];

    [[HookKitCore sharedInstance] registerModule:module withIdentifier:@"substrate"];
}
