#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <stdio.h>
#import <sys/stat.h>
#import <sys/mount.h>
#import <sys/syscall.h>
#import <sys/utsname.h>
#import <sys/syslimits.h>
#import <sys/time.h>
#import <errno.h>
#import <fcntl.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <mach-o/nlist.h>
#import <dlfcn.h>
#import <dirent.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
#import <mach/task_info.h>
#import <mach/mach_traps.h>
#import <mach/host_special_ports.h>
#import <mach/task_special_ports.h>
#import <sandbox.h>
#import <bootstrap.h>
#import <spawn.h>
#import <objc/runtime.h>

#import "../../api/Shadow.h"
#import <substrate.h>
#import <HookKit.h>

#ifdef DEBUG
#define NSLog(...) NSLog(__VA_ARGS__)
#else
#define NSLog(...) (void)0
#endif

// private symbols
#import "../../apple_priv/dyld_priv.h"
#import "../../apple_priv/codesign.h"
#import "../../apple_priv/ptrace.h"

extern Shadow* _shadow;

extern void shadowhook_DeviceCheck(HKBatchHook* hooks);
extern void shadowhook_dyld(HKBatchHook* hooks);
extern void shadowhook_libc(HKBatchHook* hooks);
extern void shadowhook_mach(HKBatchHook* hooks);
extern void shadowhook_NSArray(HKBatchHook* hooks);
extern void shadowhook_NSBundle(HKBatchHook* hooks);
extern void shadowhook_NSData(HKBatchHook* hooks);
extern void shadowhook_NSDictionary(HKBatchHook* hooks);
extern void shadowhook_NSFileHandle(HKBatchHook* hooks);
extern void shadowhook_NSFileManager(HKBatchHook* hooks);
extern void shadowhook_NSFileVersion(HKBatchHook* hooks);
extern void shadowhook_NSFileWrapper(HKBatchHook* hooks);
extern void shadowhook_NSProcessInfo(HKBatchHook* hooks);
extern void shadowhook_NSString(HKBatchHook* hooks);
extern void shadowhook_NSURL(HKBatchHook* hooks);
extern void shadowhook_objc(HKBatchHook* hooks);
extern void shadowhook_sandbox(HKBatchHook* hooks);
extern void shadowhook_syscall(HKBatchHook* hooks);
extern void shadowhook_UIApplication(HKBatchHook* hooks);
extern void shadowhook_UIImage(HKBatchHook* hooks);

extern void shadowhook_libc_extra(HKBatchHook* hooks);
extern void shadowhook_libc_envvar(HKBatchHook* hooks);
extern void shadowhook_libc_lowlevel(HKBatchHook* hooks);
extern void shadowhook_libc_antidebugging(HKBatchHook* hooks);

extern void shadowhook_dyld_extra(HKBatchHook* hooks);
extern void shadowhook_dyld_symlookup(HKBatchHook* hooks);
extern void shadowhook_dyld_updatelibs(const struct mach_header* mh, intptr_t vmaddr_slide);
extern void shadowhook_dyld_updatelibs_r(const struct mach_header* mh, intptr_t vmaddr_slide);
extern void shadowhook_dyld_shdw_add_image(const struct mach_header* mh, intptr_t vmaddr_slide);
extern void shadowhook_dyld_shdw_remove_image(const struct mach_header* mh, intptr_t vmaddr_slide);

extern void shadowhook_NSProcessInfo_fakemac(HKBatchHook* hooks);

extern void shadowhook_mem(HKBatchHook* hooks);

extern void shadowhook_objc_hidetweakclasses(HKBatchHook* hooks);
