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

- (instancetype)init {
    if((self = [super init])) {

    }

    return self;
}

- (BOOL)isPathRestricted:(NSString *)path {

    return NO;
}

- (NSDictionary *)handleMessageNamed:(NSString *)name withUserInfo:(NSDictionary *)userInfo {
    if([name isEqualToString:@"isPathRestricted"]) {
        BOOL restricted = [self isPathRestricted:userInfo[@"path"]];

        if(restricted) {
            NSLog(@"restricted path detected: %@", userInfo[@"path"]);
        }

        return @{
            @"restricted" : @(restricted)
        };
    }

    return nil;
}
@end
