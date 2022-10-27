#import "Shadow.h"

@implementation Shadow {
    NSCache* responseCache;
    CPDistributedMessagingCenter* c;
}

- (void)setMessagingCenter:(CPDistributedMessagingCenter *)center {
    c = center;
}

- (BOOL)isPathRestricted:(NSString *)path {
    if(responseCache[path]) {
        return [responseCache[path][@"restricted"] boolValue];
    }
    
    if(c) {
        NSDictionary* response = [c sendMessageAndReceiveReplyName:@"isPathRestricted" userInfo:@{
            @"path" : path
        }];

        if(response) {
            responseCache[path] = response;
            return [response[@"restricted"] boolValue];
        }
    }

    return NO;
}

- (instancetype)init {
    if((self = [super init])) {
        responseCache = [NSCache new];
        c = nil;
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
