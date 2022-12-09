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

extern void shadowhook_DeviceCheck(void);
extern void shadowhook_dyld(void);
extern void shadowhook_libc(void);
extern void shadowhook_mach(void);
extern void shadowhook_NSArray(void);
extern void shadowhook_NSBundle(void);
extern void shadowhook_NSData(void);
extern void shadowhook_NSDictionary(void);
extern void shadowhook_NSFileHandle(void);
extern void shadowhook_NSFileManager(void);
extern void shadowhook_NSFileVersion(void);
extern void shadowhook_NSFileWrapper(void);
extern void shadowhook_NSProcessInfo(void);
extern void shadowhook_NSString(void);
extern void shadowhook_NSURL(void);
extern void shadowhook_objc(void);
extern void shadowhook_sandbox(void);
extern void shadowhook_syscall(void);
extern void shadowhook_UIApplication(void);
extern void shadowhook_UIImage(void);

extern void shadowhook_libc_extra(void);
extern void shadowhook_libc_envvar(void);
extern void shadowhook_libc_lowlevel(void);
extern void shadowhook_libc_antidebugging(void);

extern void shadowhook_dyld_extra(void);
extern void shadowhook_dyld_symlookup(void);
extern void shadowhook_dyld_updatelibs(const struct mach_header* mh, intptr_t vmaddr_slide);
extern void shadowhook_dyld_updatelibs_r(const struct mach_header* mh, intptr_t vmaddr_slide);
extern void shadowhook_dyld_shdw_add_image(const struct mach_header* mh, intptr_t vmaddr_slide);
extern void shadowhook_dyld_shdw_remove_image(const struct mach_header* mh, intptr_t vmaddr_slide);

extern void shadowhook_NSProcessInfo_fakemac(void);

extern void shadowhook_mem(void);
