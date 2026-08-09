#if defined(__arm64__) && !defined(__arm64e__)
//
//  BlockHook.m
//  BlockHook
//
//  Created by 杨萧玉 on 2018/2/27.
//  Copyright © 2018年 杨萧玉. All rights reserved.
//  Thanks to MABlockClosure : https://github.com/mikeash/MABlockClosure

#import "BlockHook.h"
#import <objc/runtime.h>
#import "BHInvocation+Private.h"
#import "BHHelper.h"
#import "BHToken+Private.h"
#import "BHDealloc.h"
#import "BHToken+Private.h"
#import "BHLock.h"

#if !__has_feature(objc_arc)
#error
#endif

@implementation NSObject (BlockHook)

- (BOOL)block_checkValid {
    BOOL valid = [self isKindOfClass:NSClassFromString(@"NSBlock")];
    if (!valid) {
        NSLog(@"Not Block! %@", self);
    }
    return valid;
}

- (BHToken *)block_hookWithMode:(BlockHookMode)mode
                     usingBlock:(id)aspectBlock {
    if (!aspectBlock || ![self block_checkValid]) {
        return nil;
    }
    BHBlock *bh_block = (__bridge void *)self;
    if (!_bh_Block_descriptor_3(bh_block)) {
        NSLog(@"Block has no signature! Required ABI.2010.3.16. %@", self);
        return nil;
    }
    // Handle blocks have private data.
    dispatch_block_private_data_t dbpd = bh_dispatch_block_get_private_data(bh_block);
    if (dbpd && dbpd->dbpd_block) {
        return [dbpd->dbpd_block block_hookWithMode:mode usingBlock:aspectBlock];
    }
    return [[BHToken alloc] initWithBlock:self mode:mode aspectBlockBlock:aspectBlock];
}

- (void)block_removeAllHook {
    if (![self block_checkValid]) {
        return;
    }
    BHToken *token = nil;
    while ((token = [self block_currentHookToken])) {
        [token remove];
    }
}

- (BHToken *)block_currentHookToken {
    if (![self block_checkValid]) {
        return nil;
    }
    dispatch_block_private_data_t dbpd = bh_dispatch_block_get_private_data((__bridge BHBlock *)(self));
    if (dbpd && dbpd->dbpd_block) {
        return [dbpd->dbpd_block block_currentHookToken];
    }
    void *invoke = [self block_currentInvokeFunction];
    BHDealloc *bhDealloc = objc_getAssociatedObject(self, invoke);
    return bhDealloc.token;
}

- (void *)block_currentInvokeFunction {
    BHBlock *bh_block = (__bridge void *)self;
    BHLock *lock = [self bh_lockForKey:_cmd];
    [lock lock];
    void *invoke = bh_block->invoke;
    [lock unlock];
    return invoke;
}

- (BHToken *)block_interceptor:(void (^)(BHInvocation *invocation, IntercepterCompletion completion))interceptor {
    return [self block_hookWithMode:BlockHookModeInstead usingBlock:^(BHInvocation *invocation) {
        if (interceptor) {
            IntercepterCompletion completion = ^() {
                [invocation invokeOriginalBlock];
            };
            interceptor(invocation, completion);
            [invocation retainArguments];
        }
    }];
}

@end

#endif // arm64 only: libffi has no arm64e slice; BlockHook needs iOS 12+ (armv7 tops out at 10.3)
