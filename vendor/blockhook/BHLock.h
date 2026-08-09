//
//  BHLock.h
//  BlockHook
//
//  Created by 杨萧玉 on 2020/6/17.
//  Copyright © 2020 杨萧玉. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface BHLock : NSObject<NSLocking>

@property (nonatomic) dispatch_semaphore_t semaphore;

@end


@interface NSObject (BHLock)

- (BHLock *)bh_lockForKey:(const void * _Nonnull)key;

@end

NS_ASSUME_NONNULL_END
