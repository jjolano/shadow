//
//  BHToken+Private.h
//  BlockHook
//
//  Created by 杨萧玉 on 2020/6/17.
//  Copyright © 2020 杨萧玉. All rights reserved.
//

#import "BHToken.h"

@class BHInvocation;

NS_ASSUME_NONNULL_BEGIN

@interface BHToken (Private)

@property (nonatomic, readonly) NSMethodSignature *originalBlockSignature;
@property (nonatomic, readonly) NSMethodSignature *aspectBlockSignature;
@property (nonatomic, readonly, getter=hasStret) BOOL stret;

- (instancetype)initWithBlock:(id)block mode:(BlockHookMode)mode aspectBlockBlock:(id)aspectBlock;
- (void)invokeOriginalBlockWithArgs:(void *_Nullable *_Null_unspecified)args retValue:(void *)retValue;
- (BOOL)invokeAspectBlockWithArgs:(void *_Nullable *_Null_unspecified)args
                         retValue:(void *)retValue
                             mode:(BlockHookMode)mode
                       invocation:(BHInvocation *)invocation;

@end

NS_ASSUME_NONNULL_END
