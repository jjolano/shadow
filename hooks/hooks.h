#import "../api/Shadow.h"

#import <stdio.h>
#import <sys/stat.h>
#import <errno.h>
#import <mach-o/dyld.h>
#import <Foundation/NSFileManager.h>

extern Shadow* _shadow;

extern void shadowhook_dyld(void);
extern void shadowhook_NSFileManager(void);
extern void shadowhook_libc(void);
