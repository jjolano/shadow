#import "HKLH.h"
#import <HookKit/Core.h>

__attribute__ ((constructor)) static void module_init(void) {
    HKLH* module = [HKLH new];
    [module setFunctionHookBatchingSupported:YES];
    [module setMemoryHookBatchingSupported:YES];

    [[HookKitCore sharedInstance] registerModule:module withIdentifier:@"libhooker"];
}
