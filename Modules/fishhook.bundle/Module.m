#import "HKFH.h"
#import <HookKit/Core.h>

__attribute__ ((constructor)) static void module_init(void) {
    HKFH* module = [HKFH new];
    [module setFunctionHookBatchingSupported:YES];

    [[HookKitCore sharedInstance] registerModule:module withIdentifier:@"fishhook"];
}
