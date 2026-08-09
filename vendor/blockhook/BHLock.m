#if defined(__arm64__) && !defined(__arm64e__)
//
//  BHLock.m
//  BlockHook
//
//  Created by 杨萧玉 on 2020/6/17.
//  Copyright © 2020 杨萧玉. All rights reserved.
//

#import "BHLock.h"
#import <objc/runtime.h>

@implementation BHLock

- (instancetype)init {
    self = [super init];
    if (self) {
        _semaphore = dispatch_semaphore_create(1);
    }
    return self;
}

- (void)lock {
    dispatch_semaphore_wait(self.semaphore, DISPATCH_TIME_FOREVER);
}

- (void)unlock {
    dispatch_semaphore_signal(self.semaphore);
}

@end

@implementation NSObject (BHLock)

- (BHLock *)bh_lockForKey:(const void * _Nonnull)key {
    BHLock *lock = objc_getAssociatedObject(self, key);
    if (!lock) {
        lock = [BHLock new];
        objc_setAssociatedObject(self, key, lock, OBJC_ASSOCIATION_RETAIN);
    }
    return lock;
}

@end

#endif // arm64 only: libffi has no arm64e slice; BlockHook needs iOS 12+ (armv7 tops out at 10.3)
