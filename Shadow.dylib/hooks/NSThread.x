#import "hooks.h"

%group shadowhook_NSThread
%hook NSThread
- (NSArray *)callStackReturnAddresses {
    NSArray* result = %orig;

    if(!isCallerTweak() && result) {
        NSMutableArray* result_filtered = [result mutableCopy];

        for(NSNumber* ret_addr in result) {
            if([_shadow isAddrRestricted:[ret_addr pointerValue]]) {
                [result_filtered removeObject:ret_addr];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (NSArray *)callStackSymbols {
    if(isCallerTweak()) {
        return %orig;
    }

    // todo: properly filter this (maybe use NSPredicate?)
    return @[];
}
%end
%end

void shadowhook_NSThread(HKSubstitutor* hooks) {
    %init(shadowhook_NSThread);
}
