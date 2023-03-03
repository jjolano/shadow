#import "HKSubstitute.h"
#import <HookKit/Core.h>

__attribute__ ((constructor)) static void module_init(void) {
    HKSubstitute* module = [HKSubstitute new];
    [module setFunctionHookBatchingSupported:YES];

    [[HookKitCore sharedInstance] registerModule:module withIdentifier:@"substitute"];
}
