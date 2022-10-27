#import <HBLog.h>

#import "ShadowXPC.h"
#import "NSTask.h"

@implementation ShadowXPC {
    NSCache* responseCache;
}

- (BOOL)isPathRestricted:(NSString *)path {
    // Call dpkg to see if file is part of any installed packages on the system.
    NSTask* task = [NSTask new];
    NSPipe* stdoutPipe = [NSPipe new];

    [task setLaunchPath:@"/usr/bin/dpkg"];
    [task setArguments:@[@"-S", path]];
    [task setStandardOutput:stdoutPipe];

    HBLogDebug(@"%@%@", @"querying dpkg for: ", path);

    [task launch];
    [task waitUntilExit];

    HBLogDebug(@"%@%d", @"dpkg returned: ", [task terminationStatus]);

    if([task terminationStatus] == 0) {
        // Path found in dpkg database - exclude if base package is part of the package list.
        NSData* data = [[stdoutPipe fileHandleForReading] readDataToEndOfFile];
        NSString* output = [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];

        NSArray* result = [output componentsSeparatedByString:@":"];
        NSArray* packages = [[result objectAtIndex:0] componentsSeparatedByString:@","];

        if(![packages containsObject:@"base"] && ![packages containsObject:@" base"]) {
            return YES;
        }
    }

    return NO;
}

- (NSDictionary *)handleMessageNamed:(NSString *)name withUserInfo:(NSDictionary *)userInfo {
    NSDictionary* response = nil;

    if([name isEqualToString:@"isPathRestricted"]) {
        NSString* path = userInfo[@"path"];

        if([responseCache objectForKey:path]) {
            return [responseCache objectForKey:path];
        }

        NSString* standardizedPath = [path stringByStandardizingPath];
        BOOL restricted = [self isPathRestricted:path] || [self isPathRestricted:standardizedPath];

        NSDictionary* response = @{
            @"path" : path,
            @"standardizedPath" : standardizedPath,
            @"restricted" : @(restricted)
        };

        [responseCache setObject:response forKey:path];
    }

    return response;
}

- (instancetype)init {
    if((self = [super init])) {
        responseCache = [NSCache new];
    }

    return self;
}
@end
