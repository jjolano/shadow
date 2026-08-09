//
//  BHDealloc.h
//  BlockHook
//
//  Created by 杨萧玉 on 2020/6/17.
//  Copyright © 2020 杨萧玉. All rights reserved.
//

#import <Foundation/Foundation.h>

@class BHToken;

NS_ASSUME_NONNULL_BEGIN

@interface BHDealloc : NSObject

@property (nonatomic) BHToken *token;

@end

NS_ASSUME_NONNULL_END
