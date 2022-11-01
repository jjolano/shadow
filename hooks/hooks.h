#import "../api/Shadow.h"
#import "codesign.h"

#import <stdio.h>
#import <sys/stat.h>
#import <sys/mount.h>
#import <errno.h>
#import <fcntl.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <dirent.h>
#import <sys/sysctl.h>
#import <Foundation/Foundation.h>

extern Shadow* _shadow;

extern void shadowhook_dyld(void);
extern void shadowhook_libc(void);
extern void shadowhook_NSArray(void);
extern void shadowhook_NSBundle(void);
extern void shadowhook_NSDictionary(void);
extern void shadowhook_NSFileHandle(void);
extern void shadowhook_NSFileManager(void);
extern void shadowhook_NSFileVersion(void);
extern void shadowhook_NSFileWrapper(void);
extern void shadowhook_NSString(void);
extern void shadowhook_NSURL(void);
extern void shadowhook_UIApplication(void);
extern void shadowhook_UIImage(void);
