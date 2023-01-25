#import <Foundation/Foundation.h>
#include <unistd.h>

// Use for NSString literals or variables
#define ROOT_PATH_NS(path)([[NSFileManager defaultManager] fileExistsAtPath:path] ? path : [@"/var/jb" stringByAppendingPathComponent:path])

// Use for C string literals
#define ROOT_PATH_C(cPath) (access(cPath, F_OK) == 0) ? cPath : "/var/jb/" cPath

// Use for C string variables
// The string returned by this will get freed when your function exits
// If you want to keep it, use strdup
#define ROOT_PATH_C_VAR(cPath)(ROOT_PATH_NS([NSString stringWithUTF8String:cPath]).fileSystemRepresentation)
