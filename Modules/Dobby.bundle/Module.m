#import "HKDobby.h"
#import <HookKit/Core.h>

__attribute__ ((constructor)) static void module_init(void) {
    HKDobby* module = [HKDobby new];
    [module setFunctionHookBatchingSupported:YES];

    [[HookKitCore sharedInstance] registerModule:module withIdentifier:@"dobby"];
}
