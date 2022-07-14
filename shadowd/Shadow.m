#import "Shadow.h"

@implementation Shadow
+ (NSArray *)getURLHandlers {

    return nil;
}

- (BOOL)isPathRestricted:(NSString *)path {

    return NO;
}

- (BOOL)isURLRestricted:(NSURL *)url {

    return NO;
}

- (NSDictionary *)handleMessageNamed:(NSString *)name withUserInfo:(NSDictionary *)userInfo {
    if([name isEqualToString:@"shadowd_isRestricted"]) {
        NSURL* url = userInfo[@"url"];
        BOOL restricted = [self isURLRestricted:url];

        return @{
            @"restricted" : @(restricted)
        };
    }

    return nil;
}

- (instancetype)init {
    if((self = [super init])) {

    }

    return self;
}

+ (instancetype)sharedInstance {
    static dispatch_once_t once = 0;
    __strong static id sharedInstance = nil;

    dispatch_once(&once, ^{
        sharedInstance = [self new];
    });

    return sharedInstance;
}

+ (void)load {
    [self sharedInstance];
}
@end
