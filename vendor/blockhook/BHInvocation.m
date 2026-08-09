#if defined(__arm64__) && !defined(__arm64e__)
//
//  BHInvocation.m
//  BlockHook
//
//  Created by 杨萧玉 on 2020/6/17.
//  Copyright © 2020 杨萧玉. All rights reserved.
//

#import "BHInvocation.h"
#import "BHToken+Private.h"

@interface BHInvocation ()

@property (nonatomic, readwrite, weak) BHToken *token;
@property (nonatomic, readwrite) void *_Nullable *_Null_unspecified args;
@property (nonatomic, nullable, readwrite) void *retValue;
@property (nonatomic) void *_Nullable *_Null_unspecified realArgs;
@property (nonatomic, nullable) void *realRetValue;
@property (nonatomic, readwrite) BlockHookMode mode;
@property (nonatomic) NSMutableData *dataArgs;
@property (nonatomic) NSMutableDictionary *mallocMap;
@property (nonatomic) NSMutableDictionary *retainMap;
@property (nonatomic, getter=isArgumentsRetained, readwrite) BOOL argumentsRetained;
@property (nonatomic) dispatch_queue_t argumentsRetainedQueue;
@property (nonatomic) NSUInteger numberOfRealArgs;

@end

@implementation BHInvocation

@synthesize argumentsRetained = _argumentsRetained;

- (instancetype)initWithToken:(BHToken *)token {
    self = [super init];
    if (self) {
        _token = token;
        _argumentsRetainedQueue = dispatch_queue_create("com.blockhook.argumentsRetained", DISPATCH_QUEUE_CONCURRENT);
        NSUInteger numberOfArguments = token.originalBlockSignature.numberOfArguments;
        if (self.token.hasStret) {
            numberOfArguments++;
        }
        _numberOfRealArgs = numberOfArguments;
    }
    return self;
}

#pragma mark - getter&setter

- (BOOL)isArgumentsRetained {
    __block BOOL temp;
    dispatch_sync(self.argumentsRetainedQueue, ^{
        temp = self->_argumentsRetained;
    });
    return temp;
}

- (void)setArgumentsRetained:(BOOL)argumentsRetained {
    dispatch_barrier_async(self.argumentsRetainedQueue, ^{
        self->_argumentsRetained = argumentsRetained;
    });
}

#pragma mark - Public Method

- (void)invokeOriginalBlock {
    [self.token invokeOriginalBlockWithArgs:self.realArgs retValue:self.realRetValue];
}

- (NSMethodSignature *)methodSignature {
    return self.token.originalBlockSignature;
}

- (void)retainArguments {
    if (!self.isArgumentsRetained) {
        self.dataArgs = [NSMutableData dataWithLength:self.numberOfRealArgs * sizeof(void *)];
        self.retainMap = [NSMutableDictionary dictionaryWithCapacity:self.numberOfRealArgs + 1];
        self.mallocMap = [NSMutableDictionary dictionaryWithCapacity:self.numberOfRealArgs + 1];
        void **args = self.dataArgs.mutableBytes;
        for (NSUInteger idx = 0; idx < self.numberOfRealArgs; idx++) {
            const char *type = NULL;
            if (self.token.hasStret) {
                if (idx == 0) {
                    type = self.methodSignature.methodReturnType;
                } else {
                    type = [self.methodSignature getArgumentTypeAtIndex:idx - 1];
                }
            } else {
                type = [self.methodSignature getArgumentTypeAtIndex:idx];
            }
            args[idx] = [self _copyPointer:self.realArgs[idx] encode:type key:@(idx)];
            [self _retainPointer:args[idx] encode:type key:@(idx)];
        }
        self.realArgs = args;
        if (self.token.hasStret) {
            self.args = args + 1;
            self.retValue = *((void **)args[0]);
        } else {
            void *ret = [self _copyPointer:self.retValue encode:self.methodSignature.methodReturnType key:@-1];
            [self _retainPointer:ret encode:self.methodSignature.methodReturnType key:@-1];
            self.args = args;
            self.retValue = ret;
            self.realRetValue = ret;
        }
        
        self.argumentsRetained = YES;
    }
}

- (void)getReturnValue:(void *)retLoc {
    if (!retLoc || !self.retValue) {
        return;
    }
    NSUInteger retSize = self.methodSignature.methodReturnLength;
    memcpy(retLoc, self.retValue, retSize);
}

- (void)setReturnValue:(void *)retLoc {
    if (!retLoc || !self.retValue) {
        return;
    }
    NSUInteger retSize = self.methodSignature.methodReturnLength;
    if (self.isArgumentsRetained) {
        [self _retainPointer:retLoc encode:self.methodSignature.methodReturnType key:@-1];
    }
    memcpy(self.retValue, retLoc, retSize);
}

- (void)getArgument:(void *)argumentLocation atIndex:(NSInteger)idx {
    if (!argumentLocation || !self.args || !self.args[idx]) {
        return;
    }
    void *arg = self.args[idx];
    const char *type = [self.methodSignature getArgumentTypeAtIndex:idx];
    NSUInteger argSize;
    NSGetSizeAndAlignment(type, &argSize, NULL);
    memcpy(argumentLocation, arg, argSize);
}

- (void)setArgument:(void *)argumentLocation atIndex:(NSInteger)idx {
    if (!argumentLocation || !self.args || !self.args[idx]) {
        return;
    }
    void *arg = self.args[idx];
    const char *type = [self.methodSignature getArgumentTypeAtIndex:idx];
    NSUInteger argSize;
    NSGetSizeAndAlignment(type, &argSize, NULL);
    if (self.isArgumentsRetained) {
        [self _retainPointer:argumentLocation encode:type key:@(idx)];
    }
    memcpy(arg, argumentLocation, argSize);
}

#pragma mark - Private Helper

- (void *)_copyPointer:(void **)pointer encode:(const char *)encode key:(NSNumber *)key {
    NSUInteger pointerSize;
    NSGetSizeAndAlignment(encode, &pointerSize, NULL);
    NSMutableData *pointerData = [NSMutableData dataWithLength:pointerSize];
    self.mallocMap[key] = pointerData;
    void *pointerBuf = pointerData.mutableBytes;
    memcpy(pointerBuf, pointer, pointerSize);
    return pointerBuf;
}

- (void)_retainPointer:(void **)pointer encode:(const char *)encode key:(NSNumber *)key {
    if (!pointer || (*encode != '@' && *encode != '*')) {
        return;
    }
    void *p = *pointer;
    if (!p) {
        return;
    }
    if (encode[0] == '@') {
        id arg = (__bridge id)p;
        if ([arg isKindOfClass:NSClassFromString(@"NSBlock")]) {
            self.retainMap[key] = [arg copy];
        } else {
            self.retainMap[key] = arg;
        }
    } else if (encode[0] == '*') {
        char *arg = p;
        NSMutableData *data = [NSMutableData dataWithLength:sizeof(char) * strlen(arg)];
        self.retainMap[key] = data;
        char *str = data.mutableBytes;
        strcpy(str, arg);
        *pointer = str;
    }
}

@end

#endif // arm64 only: libffi has no arm64e slice; BlockHook needs iOS 12+ (armv7 tops out at 10.3)
