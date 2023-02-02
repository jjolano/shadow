#import "hooks.h"

%group shadowhook_NSThread
%hook NSThread
- (NSArray *)callStackReturnAddresses {
    NSArray* result = %orig;

    if(!isCallerTweak() && result) {
        NSMutableArray* result_filtered = [NSMutableArray new];

        for(NSNumber* ret_addr in result) {
            if(![_shadow isAddrRestricted:[ret_addr pointerValue]]) {
                [result_filtered addObject:ret_addr];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}
%end
%end

void shadowhook_NSThread(HKSubstitutor* hooks) {
    %init(shadowhook_NSThread);
}
