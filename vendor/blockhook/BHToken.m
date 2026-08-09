#if defined(__arm64__) && !defined(__arm64e__)
//
//  BHToken.m
//  BlockHook
//
//  Created by 杨萧玉 on 2020/6/17.
//  Copyright © 2020 杨萧玉. All rights reserved.
//

#import "BHToken.h"
#if COCOAPODS
#import "ffi.h"
#else
#import <ffi.h>
#endif
#import <dlfcn.h>
#import <objc/runtime.h>

#import "BHHelper.h"
#import "BHDealloc.h"
#import "BlockHook.h"
#import "BHLock.h"
#import "BHInvocation+Private.h"


@interface BHToken () {
    ffi_cif _cif;
    void *_replacementInvoke;
    ffi_closure *_closure;
}

@property (nonatomic, readwrite) BlockHookMode mode;
@property (nonatomic) NSMutableArray *allocations;
@property (nonatomic, weak, readwrite) id block;
@property (nonatomic, readwrite) id aspectBlock;
@property (nonatomic, nullable, readwrite) NSString *mangleName;
@property (nonatomic) NSMethodSignature *originalBlockSignature;
@property (nonatomic) NSMethodSignature *aspectBlockSignature;
@property (atomic) void *originInvoke;
@property (nonatomic, readwrite) NSMutableDictionary *userInfo;

/**
 if block is kind of `__NSStackBlock__` class.
 */
@property (nonatomic, getter=isStackBlock) BOOL stackBlock;
@property (nonatomic, getter=hasStret) BOOL stret;
@property (nonatomic, nullable, readwrite) BHToken *next;

@end

@implementation BHToken

@synthesize next = _next;

- (instancetype)initWithBlock:(id)block
                         mode:(BlockHookMode)mode
             aspectBlockBlock:(id)aspectBlock {
    self = [super init];
    if (self) {
        _allocations = [[NSMutableArray alloc] init];
        _block = block;
        const char *encode = BHBlockTypeEncodeString(block);
        // Check block encoding types valid.
        NSUInteger numberOfArguments = [self _prepCIF:&_cif withEncodeString:encode];
        if (numberOfArguments == -1) { // Unknown encode.
            return nil;
        }
        // Check aspectBlock valid.
        _aspectBlockSignature = [NSMethodSignature signatureWithObjCTypes:BHBlockTypeEncodeString(aspectBlock)];
        _userInfo = [NSMutableDictionary dictionary];
        _originalBlockSignature = [NSMethodSignature signatureWithObjCTypes:encode];
        _closure = ffi_closure_alloc(sizeof(ffi_closure), &_replacementInvoke);
        
        // __NSStackBlock__ -> __NSStackBlock -> NSBlock
        if ([block isKindOfClass:NSClassFromString(@"__NSStackBlock")]) {
            NSLog(@"Hooking StackBlock causes a memory leak! I suggest you copy it first!");
            self.stackBlock = YES;
        }

        BOOL success = [self _prepClosure];
        if (!success) {
            return nil;
        }
        BHDealloc *bhDealloc = [BHDealloc new];
        bhDealloc.token = self;
        objc_setAssociatedObject(block, _replacementInvoke, bhDealloc, OBJC_ASSOCIATION_RETAIN);
        _mode = mode;
        // If aspectBlock is a NSStackBlock and invoked asynchronously, it will cause a wild pointer. We copy it.
        _aspectBlock = [aspectBlock copy];
    }
    return self;
}

- (void)dealloc {
    if (_closure) {
        ffi_closure_free(_closure);
        _closure = NULL;
    }
}

- (BHToken *)next {
    BHLock *lock = [self.block bh_lockForKey:@selector(next)];
    [lock lock];
    if (!_next) {
        BHDealloc *bhDealloc = objc_getAssociatedObject(self.block, self.originInvoke);
        _next = bhDealloc.token;
    }
    BHToken *result = _next;
    [lock unlock];
    return result;
}

- (void)setNext:(BHToken *)next {
    BHLock *lock = [self.block bh_lockForKey:@selector(next)];
    [lock lock];
    _next = next;
    [lock unlock];
}

- (BOOL)remove {
    if (self.isStackBlock) {
        NSLog(@"Can't remove token for StackBlock!");
        return NO;
    }
    if (!self.originInvoke) {
        return NO;
    }
    if (self.block) {
        BHToken *current = [self.block block_currentHookToken];
        
        for (BHToken *last = nil; current; last = current, current = [current next]) {
            if (current != self) {
                continue;
            }
            if (last) { // remove middle token
                last.originInvoke = self.originInvoke;
                last.next = nil;
            } else { // remove head(current) token
                BHLock *lock = [self.block bh_lockForKey:@selector(block_currentInvokeFunction)];
                [lock lock];
                BOOL success = ReplaceBlockInvoke(((__bridge BHBlock *)self.block), self.originInvoke);
                if (!success) {
                    NSLog(@"Remove failed! Replace invoke pointer failed. Block:%@", self.block);
                    [lock unlock];
                    return NO;
                }
                [lock unlock];
            }
            break;
        }
    }
    self.originInvoke = NULL;
    objc_setAssociatedObject(self.block, _replacementInvoke, nil, OBJC_ASSOCIATION_RETAIN);
    return YES;
}

- (NSString *)mangleName {
    if (!_mangleName) {
        NSString *mangleName = self.next.mangleName;
        if (mangleName.length > 0) {
            _mangleName = mangleName;
        } else {
            Dl_info dlinfo;
            memset(&dlinfo, 0, sizeof(dlinfo));
            if (dladdr(self.originInvoke, &dlinfo) && dlinfo.dli_sname) {
                _mangleName = [NSString stringWithUTF8String:dlinfo.dli_sname];
            }
        }
    }
    return _mangleName;
}

- (void)invokeOriginalBlockWithArgs:(void **)args retValue:(void *)retValue {
    if (self.originInvoke) {
        ffi_call(&_cif, self.originInvoke, retValue, args);
    } else {
        NSLog(@"You had lost your originInvoke! Please check the order of removing tokens!");
    }
}

#pragma mark - Private Method

- (void *)_allocate:(size_t)howmuch {
    NSMutableData *data = [NSMutableData dataWithLength:howmuch];
    [self.allocations addObject:data];
    return data.mutableBytes;
}

- (ffi_type *)_ffiTypeForStructEncode:(const char *)str {
    NSUInteger size, align;
    long length;
    BHSizeAndAlignment(str, &size, &align, &length);
    ffi_type *structType = [self _allocate:sizeof(*structType)];
    structType->type = FFI_TYPE_STRUCT;
    
    const char *temp = [[[NSString stringWithUTF8String:str] substringWithRange:NSMakeRange(0, length)] UTF8String];
    
    // cut "struct="
    while (temp && *temp && *temp != '=') {
        temp++;
    }
    int elementCount = 0;
    ffi_type **elements = [self _typesWithEncodeString:temp + 1 getCount:&elementCount startIndex:0 nullAtEnd:YES];
    if (!elements) {
        return nil;
    }
    structType->elements = elements;
    return structType;
}

#define SINT(type) do { \
    if (str[0] == @encode(type)[0]) { \
        if (sizeof(type) == 1) { \
            return &ffi_type_sint8; \
        } else if (sizeof(type) == 2) { \
            return &ffi_type_sint16; \
        } else if (sizeof(type) == 4) { \
            return &ffi_type_sint32; \
        } else if (sizeof(type) == 8) { \
            return &ffi_type_sint64; \
        } else { \
            NSLog(@"Unknown size for type %s", #type); \
            abort(); \
        } \
    } \
} while(0)

#define UINT(type) do { \
    if (str[0] == @encode(type)[0]) { \
        if (sizeof(type) == 1) { \
            return &ffi_type_uint8; \
        } else if (sizeof(type) == 2) { \
            return &ffi_type_uint16; \
        } else if (sizeof(type) == 4) { \
            return &ffi_type_uint32; \
        } else if (sizeof(type) == 8) { \
            return &ffi_type_uint64; \
        } else { \
            NSLog(@"Unknown size for type %s", #type); \
            abort(); \
        } \
    } \
} while(0)

#define INT(type) do { \
    SINT(type); \
    UINT(unsigned type); \
} while(0)

#define COND(type, name) do { \
    if (str[0] == @encode(type)[0]) { \
        return &ffi_type_ ## name; \
    } \
} while(0)

#define PTR(type) COND(type, pointer)

- (ffi_type *)_ffiTypeForEncode:(const char *)str {
    SINT(_Bool);
    SINT(signed char);
    UINT(unsigned char);
    INT(short);
    INT(int);
    INT(long);
    INT(long long);
    
    PTR(id);
    PTR(Class);
    PTR(SEL);
    PTR(void *);
    PTR(char *);
    
    COND(float, float);
    COND(double, double);
    
    COND(void, void);
    
    // Ignore Method Encodings
    switch (*str) {
        case 'r':
        case 'R':
        case 'n':
        case 'N':
        case 'o':
        case 'O':
        case 'V':
            return [self _ffiTypeForEncode:str + 1];
    }
    
    // Struct Type Encodings
    if (*str == '{') {
        ffi_type *structType = [self _ffiTypeForStructEncode:str];
        return structType;
    }
    
    NSLog(@"Unknown encode string %s", str);
    return nil;
}

- (ffi_type **)_argsWithEncodeString:(const char *)str getCount:(int *)outCount {
    // 第一个是返回值，需要排除
    return [self _typesWithEncodeString:str getCount:outCount startIndex:1];
}

- (ffi_type **)_typesWithEncodeString:(const char *)str
                             getCount:(int *)outCount
                           startIndex:(int)start {
    return [self _typesWithEncodeString:str getCount:outCount startIndex:start nullAtEnd:NO];
}

- (ffi_type **)_typesWithEncodeString:(const char *)str
                             getCount:(int *)outCount
                           startIndex:(int)start
                            nullAtEnd:(BOOL)nullAtEnd {
    int argCount = BHTypeCount(str) - start;
    ffi_type **argTypes = [self _allocate:(argCount + (nullAtEnd ? 1 : 0)) * sizeof(*argTypes)];
    
    int i = -start;
    while(str && *str) {
        const char *next = BHSizeAndAlignment(str, NULL, NULL, NULL);
        if (i >= 0 && i < argCount) {
            ffi_type *argType = [self _ffiTypeForEncode:str];
            if (argType) {
                argTypes[i] = argType;
            } else {
                if (outCount) {
                    *outCount = -1;
                }
                return nil;
            }
        }
        i++;
        str = next;
    }
    
    if (nullAtEnd) {
        argTypes[argCount] = NULL;
    }
    
    if (outCount) {
        *outCount = argCount;
    }
    
    return argTypes;
}

- (int)_prepCIF:(ffi_cif *)cif withEncodeString:(const char *)str {
    int argCount;
    ffi_type **argTypes;
    ffi_type *returnType;
    BHBlock *bh_block = (__bridge void *)self.block;
    if (bh_block->flags & BLOCK_HAS_STRET) {
        argTypes = [self _typesWithEncodeString:str getCount:&argCount startIndex:0];
        if (!argTypes) { // Error!
            return -1;
        }
        argTypes[0] = &ffi_type_pointer;
        returnType = &ffi_type_void;
        self.stret = YES;
    } else {
        argTypes = [self _argsWithEncodeString:str getCount:&argCount];
        if (!argTypes) { // Error!
            return -1;
        }
        returnType = [self _ffiTypeForEncode:str];
    }
    if (!returnType) { // Error!
        return -1;
    }
    ffi_status status = ffi_prep_cif(cif, FFI_DEFAULT_ABI, argCount, returnType, argTypes);
    if (status != FFI_OK) {
        NSLog(@"Got result %ld from ffi_prep_cif", (long)status);
        abort();
    }
    return argCount;
}

- (BOOL)_prepClosure {
    ffi_status status = ffi_prep_closure_loc(_closure, &_cif, BHFFIClosureFunc, (__bridge void *)(self), _replacementInvoke);
    if (status != FFI_OK) {
        NSLog(@"Hook failed! ffi_prep_closure returned %d", (int)status);
        return NO;
    }
    // exchange invoke func imp
    BHBlock *block = (__bridge BHBlock *)self.block;
    BHLock *lock = [self.block bh_lockForKey:@selector(block_currentInvokeFunction)];
    [lock lock];
    self.originInvoke = block->invoke;
    BOOL success = ReplaceBlockInvoke(block, _replacementInvoke);
    if (!success) {
        NSLog(@"Hook failed! Replace invoke pointer failed. Block:%@", self.block);
        [lock unlock];
        return NO;
    }
    [lock unlock];
    return YES;
}

- (BOOL)invokeAspectBlockWithArgs:(void **)args
                         retValue:(void *)retValue
                             mode:(BlockHookMode)mode
                       invocation:(BHInvocation *)invocation {
    if (!self.isStackBlock && !self.block) {
        return NO;
    }
    invocation.mode = mode;
    NSInvocation *blockInvocation = [NSInvocation invocationWithMethodSignature:self.aspectBlockSignature];
    if (self.aspectBlockSignature.numberOfArguments > 1) {
        [blockInvocation setArgument:(void *)&invocation atIndex:1];
    }
    
    // origin block invoke func arguments: block(self), ...
    // origin block invoke func arguments (x86 struct return): struct*, block(self), ...
    // hook block signature arguments: block(self), invocation, ...
    NSUInteger numberOfArguments = MIN(self.aspectBlockSignature.numberOfArguments,
                                       self.originalBlockSignature.numberOfArguments + 1);
    for (NSUInteger idx = 2; idx < numberOfArguments; idx++) {
        [blockInvocation setArgument:args[idx - 1] atIndex:idx];
    }
    [blockInvocation invokeWithTarget:self.aspectBlock];
    return YES;
}

@end

#endif // arm64 only: libffi has no arm64e slice; BlockHook needs iOS 12+ (armv7 tops out at 10.3)
