#if defined(__arm64__) && !defined(__arm64e__)
//
//  BHHelper.m
//  BlockHook
//
//  Created by 杨萧玉 on 2020/6/17.
//  Copyright © 2020 杨萧玉. All rights reserved.
//

#import "BHHelper.h"
#import "BHInvocation+Private.h"
#import "BHToken+Private.h"
#import <mach/vm_map.h>
#import <mach/mach_init.h>

#pragma mark - Helper Function

bool BlockHookModeContainsMode(BlockHookMode m1, BlockHookMode m2) {
    return ((m1 & m2) == m2);
}

__unused BHBlockDescriptor1 * _bh_Block_descriptor_1(BHBlock *aBlock) {
    return aBlock->descriptor;
}

__unused BHBlockDescriptor2 * _bh_Block_descriptor_2(BHBlock *aBlock) {
    if (!(aBlock->flags & BLOCK_HAS_COPY_DISPOSE)) {
        return nil;
    }
    uint8_t *desc = (uint8_t *)aBlock->descriptor;
    desc += sizeof(BHBlockDescriptor1);
    return (BHBlockDescriptor2 *)desc;
}

BHBlockDescriptor3 * _bh_Block_descriptor_3(BHBlock *aBlock) {
    if (!(aBlock->flags & BLOCK_HAS_SIGNATURE)) {
        return nil;
    }
    uint8_t *desc = (uint8_t *)aBlock->descriptor;
    desc += sizeof(BHBlockDescriptor1);
    if (aBlock->flags & BLOCK_HAS_COPY_DISPOSE) {
        desc += sizeof(BHBlockDescriptor2);
    }
    return (BHBlockDescriptor3 *)desc;
}

static dispatch_block_t blockWithPrivateData;
#define DISPATCH_BLOCK_PRIVATE_DATA_MAGIC 0xD159B10C // 0xDISPatch_BLOCk

DISPATCH_ALWAYS_INLINE
inline dispatch_block_private_data_t
bh_dispatch_block_get_private_data(BHBlock *block) {
    if (!blockWithPrivateData) {
        blockWithPrivateData = dispatch_block_create(0, ^{});
    }
    if (block->invoke != ((__bridge BHBlock *)blockWithPrivateData)->invoke) {
        return nil;
    }
    // Keep in sync with _dispatch_block_create implementation
    uint8_t *privateData = (uint8_t *)block;
    // privateData points to base of struct Block_layout
    privateData += sizeof(BHBlock);
    // privateData points to base of captured dispatch_block_private_data_s object
    dispatch_block_private_data_t dbpd = (dispatch_block_private_data_t)privateData;
    if (dbpd->dbpd_magic != DISPATCH_BLOCK_PRIVATE_DATA_MAGIC) {
        return nil;
    }
    return dbpd;
}

const char *BHSizeAndAlignment(const char *str, NSUInteger *sizep, NSUInteger *alignp, long *lenp) {
    const char *out = NSGetSizeAndAlignment(str, sizep, alignp);
    if (lenp) {
        *lenp = out - str;
    }
    while(*out == '}') {
        out++;
    }
    while(isdigit(*out)) {
        out++;
    }
    return out;
}

int BHTypeCount(const char *str) {
    int typeCount = 0;
    while(str && *str) {
        str = BHSizeAndAlignment(str, NULL, NULL, NULL);
        typeCount++;
    }
    return typeCount;
}

const char *BHBlockTypeEncodeString(id blockObj) {
    BHBlock *block = (__bridge void *)blockObj;
    return _bh_Block_descriptor_3(block)->signature;
}

vm_prot_t ProtectInvokeVMIfNeed(void *address) {
    vm_address_t addr = (vm_address_t)address;
    vm_size_t vmsize = 0;
    mach_port_t object = 0;
#if defined(__LP64__) && __LP64__
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t infoCnt = VM_REGION_BASIC_INFO_COUNT_64;
    kern_return_t ret = vm_region_64(mach_task_self(), &addr, &vmsize, VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &infoCnt, &object);
#else
    vm_region_basic_info_data_t info;
    mach_msg_type_number_t infoCnt = VM_REGION_BASIC_INFO_COUNT;
    kern_return_t ret = vm_region(mach_task_self(), &addr, &vmsize, VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &infoCnt, &object);
#endif
    if (ret != KERN_SUCCESS) {
        NSLog(@"vm_region block invoke pointer failed! ret:%d, addr:%p", ret, address);
        return VM_PROT_NONE;
    }
    vm_prot_t protection = info.protection;
    if ((protection&VM_PROT_WRITE) == 0) {
        ret = vm_protect(mach_task_self(), (vm_address_t)address, sizeof(address), false, protection|VM_PROT_WRITE);
        if (ret != KERN_SUCCESS) {
            NSLog(@"vm_protect block invoke pointer VM_PROT_WRITE failed! ret:%d, addr:%p", ret, address);
            return VM_PROT_NONE;
        }
    }
    return protection;
}

BOOL ReplaceBlockInvoke(BHBlock *block, void *replacement) {
    void *address = &(block->invoke);
    vm_prot_t origProtection = ProtectInvokeVMIfNeed(address);
    if (origProtection == VM_PROT_NONE) {
        return NO;
    }
    block->invoke = replacement;
    if ((origProtection&VM_PROT_WRITE) == 0) {
        kern_return_t ret = vm_protect(mach_task_self(), (vm_address_t)address, sizeof(address), false, origProtection);
        if (ret != KERN_SUCCESS) {
            NSLog(@"vm_protect block invoke pointer REVERT failed! ret:%d, addr:%p", ret, address);
        }
    }
    return YES;
}

#pragma mark - Hook Function

void BHFFIClosureFunc(ffi_cif *cif, void *ret, void **args, void *userdata) {
    BHToken *token = (__bridge BHToken *)(userdata);
    void *userRet = ret;
    void **userArgs = args;
    if (token.hasStret) {
        // The first arg contains address of a pointer of returned struct.
        userRet = *((void **)args[0]);
        // Other args move backwards.
        userArgs = args + 1;
    }
    *(void **)userRet = NULL;
    BHInvocation *invocation = [[BHInvocation alloc] initWithToken:token];
    invocation.args = userArgs;
    invocation.retValue = userRet;
    invocation.realArgs = args;
    invocation.realRetValue = ret;
    if (BlockHookModeContainsMode(token.mode, BlockHookModeBefore)) {
        [token invokeAspectBlockWithArgs:userArgs retValue:userRet mode:BlockHookModeBefore invocation:invocation];
    }
    if (!(BlockHookModeContainsMode(token.mode, BlockHookModeInstead) &&
          [token invokeAspectBlockWithArgs:userArgs retValue:userRet mode:BlockHookModeInstead invocation:invocation])) {
        [token invokeOriginalBlockWithArgs:args retValue:ret];
    }
    if (BlockHookModeContainsMode(token.mode, BlockHookModeAfter)) {
        [token invokeAspectBlockWithArgs:userArgs retValue:userRet mode:BlockHookModeAfter invocation:invocation];
    }
}

#endif // arm64 only: libffi has no arm64e slice; BlockHook needs iOS 12+ (armv7 tops out at 10.3)
