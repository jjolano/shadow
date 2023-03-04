#import "HKElleKit.h"
#import <HookKit/Core.h>

__attribute__ ((constructor)) static void module_init(void) {
    HKElleKit* module = [HKElleKit new];
    [module setFunctionHookBatchingSupported:YES];
    [module setMemoryHookBatchingSupported:YES];

    [[HookKitCore sharedInstance] registerModule:module withIdentifier:@"ellekit"];
}
