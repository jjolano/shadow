#import "HKDobby.h"
#import <HookKit/Core.h>

__attribute__ ((constructor)) static void module_init(void) {
    HKDobby* module = [HKDobby new];

    // technically it doesn't support batch hooking but we want to override the method since
    // we need to use dobby's trampoline functions before hooking
    [module setFunctionHookBatchingSupported:YES];
    [module setNullImageSearchSupported:YES];

    [[HookKitCore sharedInstance] registerModule:module withIdentifier:@"dobby"];
}
