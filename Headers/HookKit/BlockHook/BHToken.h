//
//  BHToken.h
//  BlockHook
//
//  Created by 杨萧玉 on 2020/6/17.
//  Copyright © 2020 杨萧玉. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_OPTIONS(NSUInteger, BlockHookMode) {
    BlockHookModeBefore = 1 << 0,
    BlockHookModeInstead = 1 << 1,
    BlockHookModeAfter = 1 << 2,
    BlockHookModeDead = 1 << 3,
};

NS_ASSUME_NONNULL_BEGIN

@interface BHToken : NSObject

/**
 Mode you want to insert your custom logic: Before, Instead, After AND Dead.
 This is NS_OPTIONS, so you can use bitmask.
 */
@property (nonatomic, readonly) BlockHookMode mode;

/**
 Block be hooked.
 */
@property (nonatomic, weak, readonly) id block;

/**
 Next token in hook list.
 */
@property (nonatomic, nullable, readonly) BHToken *next;

/**
 Mangle name of the invoke function.
 */
@property (nonatomic, nullable, readonly) NSString *mangleName;

/**
 Aspect Block.
 */
@property (nonatomic, readonly) id aspectBlock;

/**
 A dictionary containing user-defined information relating to the token.
 */
@property (nonatomic, readonly) NSMutableDictionary *userInfo;

/**
 Remove token will revert the hook.

 @return If it is successful.
 */
- (BOOL)remove;

@end

NS_ASSUME_NONNULL_END
