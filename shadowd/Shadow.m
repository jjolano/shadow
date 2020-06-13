#import "Shadow.h"

@implementation Shadow
+ (void)load {
    [self sharedInstance];
}

+ (instancetype)sharedInstance {
    static dispatch_once_t once = 0;
    __strong static id sharedInstance = nil;

    dispatch_once(&once, ^{
        sharedInstance = [self new];
    });

    return sharedInstance;
}

- (BOOL)isPathRestricted:(NSString *)path {

    return NO;
}

- (NSDictionary *)handleMessageNamed:(NSString *)name withUserInfo:(NSDictionary *)userInfo {
    HBLogDebug(@"[shadow] handleMessageNamed:%@ from %@", name, userInfo[@"bundleIdentifier"]);

    if([name isEqualToString:@"isPathRestricted"]) {
        BOOL restricted = [self isPathRestricted:userInfo[@"path"]];

        HBLogDebug(@"[shadow] isPathRestricted:%@: %s", userInfo[@"path"], restricted ? "restricted" : "permitted");

        return @{
            @"restricted" : @(restricted)
        };
    }

    return nil;
}

- (instancetype)init {
    if((self = [super init])) {
        
        HBLogInfo(@"[shadow] initialized Shadow instance");
    }

    return self;
}
@end
