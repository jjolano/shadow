//
//  BHInvocation+Private.h
//  BlockHook
//
//  Created by 杨萧玉 on 2020/6/17.
//  Copyright © 2020 杨萧玉. All rights reserved.
//

#import "BHInvocation.h"

@class BHToken;

NS_ASSUME_NONNULL_BEGIN

@interface BHInvocation (Private)

@property (nonatomic, readwrite) BlockHookMode mode;
/**
Arguments of invoking the block. Need type casting.
*/
@property (nonatomic, readwrite) void *_Nullable *_Null_unspecified args;
/**
Return value of invoking the block. Need type casting.
*/
@property (nonatomic, nullable, readwrite) void *retValue;
@property (nonatomic) void *_Nullable *_Null_unspecified realArgs;
@property (nonatomic, nullable) void *realRetValue;

- (instancetype)initWithToken:(BHToken *)token;

@end

NS_ASSUME_NONNULL_END
