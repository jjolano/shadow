#import "RestrictionResolver.h"
#import <Shadow/Core.h>
#import <Shadow/Core+Utilities.h>

#import <limits.h>
#import <unistd.h>

// Reentrancy guard for the resolve-before-exempt step: the libc realpath hook
// (hooks/libc.x) re-enters the engine from realpath — this code calls
// realpath from inside the engine, so without a per-thread guard the
// hook → engine → realpath → hook cycle would recurse forever. _Thread_local
// is exactly right: the only recursion is same-thread.
static _Thread_local BOOL shdw_resolver_resolving = NO;

@implementation ShadowRestrictionResolver {
    ShadowRestrictionContext _context;
}

- (instancetype)initWithContext:(ShadowRestrictionContext)context {
    if((self = [super init])) {
        _context = context;
    }

    return self;
}

- (NSString *)expandTilde:(NSString *)path {
    path = [path stringByExpandingTildeInPath];

    if([path characterAtIndex:0] == '~') {
        return nil;
    }

    return path;
}

- (NSString *)joinWorkingDirectory:(NSString *)path workingDirectory:(NSString *)wd {
    if(!wd || ![wd isAbsolutePath]) {
        wd = [[NSFileManager defaultManager] currentDirectoryPath];
    }

    return [wd stringByAppendingPathComponent:path];
}

- (NSString *)standardizePath:(NSString *)path {
    return [Shadow getStandardizedPath:path];
}

- (BOOL)isSandboxExempt:(NSString *)path {
    return _context.hasAppSandbox
        && ([path hasPrefix:_context.bundlePath] || [path hasPrefix:_context.homePath]);
}

- (NSString *)resolveTarget:(NSString *)path {
    // The guard's check-and-set around realpath: re-entered engine runs see
    // the flag and skip their own realpath.
    if(shdw_resolver_resolving) {
        return nil;
    }

    shdw_resolver_resolving = YES;

    char resolved[PATH_MAX];
    BOOL ok = (realpath([path fileSystemRepresentation], resolved) != NULL);

    shdw_resolver_resolving = NO;
    return ok ? [NSString stringWithUTF8String:resolved] : nil;
}
@end