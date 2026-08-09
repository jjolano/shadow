//
//  BlockHook.h
//  BlockHook
//
//  Created by 杨萧玉 on 2018/2/27.
//  Copyright © 2018年 杨萧玉. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "BHToken.h"
#import "BHInvocation.h"

NS_ASSUME_NONNULL_BEGIN

/**
 BlockHook Category.
 Method receiver must be a block.
 */
@interface NSObject (BlockHook)

/**
 Hook this block.

 @param mode BlockHookMode
 @param aspectBlock Implement your custom logic here. Argument list: BHInvocation comes in first, followed by other arguments when block invoking.
 @return Token for hook.
 */
- (nullable BHToken *)block_hookWithMode:(BlockHookMode)mode
                              usingBlock:(id)aspectBlock;

/**
 Remove all hook.
 */
- (void)block_removeAllHook;

/**
 Block may be hooked more than once. The current token represents the last time.

 @return BHToken instance.
 */
- (nullable BHToken *)block_currentHookToken;

/**
 Current invoke function of block.

 @return Pointer to invoke function.
 */
- (void *)block_currentInvokeFunction;

typedef void(^IntercepterCompletion)(void);

/**
 Interceptor for blocks. When your interceptor completed, call `completion` callback.
 You can call `completion` asynchronously!

 @param interceptor You **MUST** call `completion` callback in interceptor, unless you want to cancel invocation.
 @return BHToken instance.
 */
- (BHToken *)block_interceptor:(void (^)(BHInvocation *invocation, IntercepterCompletion completion))interceptor;

@end

NS_ASSUME_NONNULL_END
