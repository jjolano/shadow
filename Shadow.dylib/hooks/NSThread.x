#import "hooks.h"

%group shadowhook_NSThread
%hook NSThread
+ (NSArray *)callStackReturnAddresses {
    NSArray* result = %orig;

    if(isCallerExternal() && result) {
        NSMutableArray* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSNumber* ret_addr in result) {
            if(![_shadow isAddrRestricted:[ret_addr pointerValue]]) {
                [result_filtered addObject:ret_addr];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

+ (NSArray *)callStackSymbols {
    NSArray* result = %orig;

    if(isCallerExternal() && result) {
        NSMutableArray* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSString* line in result) {
            // Frame format: "index  image  address  symbol + offset". The
            // address field is the third non-empty whitespace-separated
            // component. Only frames whose address resolves into a
            // restricted image are dropped; unparsable or benign lines are
            // preserved so the caller never gets an empty trace wholesale.
            NSArray<NSString *>* parts = [line componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            NSMutableArray<NSString *>* fields = [NSMutableArray arrayWithCapacity:parts.count];

            for(NSString* part in parts) {
                if(part.length > 0) {
                    [fields addObject:part];
                }
            }

            if(fields.count >= 3 && [fields[2] hasPrefix:@"0x"] && fields[2].length > 2) {
                unsigned long long value = strtoull(fields[2].UTF8String, NULL, 16);

                if(value != 0 && [_shadow isAddrRestricted:(void *)(uintptr_t)value]) {
                    continue;
                }
            }

            [result_filtered addObject:line];
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
