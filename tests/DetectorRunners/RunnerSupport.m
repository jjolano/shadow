#import "RunnerSupport.h"
#import "RunnerSupportC.h"

#import <arpa/inet.h>
#import <errno.h>
#import <netinet/in.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>
#import <sys/socket.h>
#import <unistd.h>

static NSString *SHDWRunnerQueryValue(NSURL *url, NSString *name) {
    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    for (NSURLQueryItem *item in components.queryItems) {
        if ([item.name isEqualToString:name]) return item.value;
    }
    return nil;
}

NSDictionary *SHDWRunnerParameters(NSURL *url) {
    if (!url) return @{};
    NSString *callback = SHDWRunnerQueryValue(url, @"callback");
    if (!callback.length) return @{};
    return @{
        @"nonce": SHDWRunnerQueryValue(url, @"nonce") ?: @"",
        @"callback": callback,
    };
}

static BOOL SHDWRunnerWrite(int fd, const void *bytes, size_t length) {
    const uint8_t *cursor = bytes;
    while (length) {
        ssize_t written = write(fd, cursor, length);
        if (written <= 0) return NO;
        cursor += written;
        length -= (size_t)written;
    }
    return YES;
}

static NSString *SHDWRunnerCallbackValue(NSURL *url, NSString *name) {
    return SHDWRunnerQueryValue(url, name);
}

BOOL SHDWRunnerSendReport(NSDictionary *report, NSString *callbackURLString) {
    if (!report || !callbackURLString.length) return NO;
    NSDictionary *sdk = [report[@"sdk"] isKindOfClass:[NSDictionary class]] ? report[@"sdk"] : nil;
    NSString *identifier = [sdk[@"id"] isKindOfClass:[NSString class]] ? sdk[@"id"] : nil;
    if (!identifier.length) return NO;
    NSError *error = nil;
    NSData *reportData = [NSJSONSerialization dataWithJSONObject:report options:0 error:&error];
    if (!reportData || reportData.length > UINT32_MAX) return NO;

    NSURL *callbackURL = [NSURL URLWithString:callbackURLString];
    NSString *host = callbackURL.host.lowercaseString;
    NSNumber *portNumber = callbackURL.port;
    NSString *nonce = SHDWRunnerCallbackValue(callbackURL, @"nonce");
    if (![host isEqualToString:@"127.0.0.1"] || !portNumber || !nonce.length) return NO;

    NSMutableDictionary *envelope = [@{
        @"nonce": nonce,
        @"identifier": identifier,
        @"report": report,
    } mutableCopy];
    NSData *envelopeData = [NSJSONSerialization dataWithJSONObject:envelope options:0 error:&error];
    if (!envelopeData || envelopeData.length > UINT32_MAX) return NO;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NO;
    struct timeval timeout = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in address = {0};
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = htons(portNumber.unsignedShortValue);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    BOOL connected = connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0;
    uint32_t length = htonl((uint32_t)envelopeData.length);
    BOOL sent = connected && SHDWRunnerWrite(fd, &length, sizeof(length)) &&
        SHDWRunnerWrite(fd, envelopeData.bytes, envelopeData.length);
    shutdown(fd, SHUT_RDWR);
    close(fd);
    if (sent) exit(0);
    return NO;
}

BOOL SHDWRunnerFinish(NSString *identifier,
                     NSString *name,
                     NSString *version,
                     NSString *outcome,
                     NSArray *rounds,
                     NSDictionary *timing,
                     NSString *callbackURLString) {
    if (!identifier.length || !callbackURLString.length) return NO;
    NSMutableDictionary *report = [@{
        @"schemaVersion": @1,
        @"sdk": @{
            @"id": identifier,
            @"name": name ?: identifier,
            @"version": version ?: @"unknown",
        },
        @"outcome": outcome ?: @"error",
        @"rounds": rounds ?: @[],
        @"generatedAt": [NSISO8601DateFormatter.new stringFromDate:[NSDate date]],
    } mutableCopy];
    if (timing) report[@"timing"] = timing;
    return SHDWRunnerSendReport(report, callbackURLString);
}

int SHDWRunnerSendJSON(const char *reportJSON, const char *callbackURL) {
    if (!reportJSON || !callbackURL) return 0;
    NSData *data = [NSData dataWithBytes:reportJSON length:strlen(reportJSON)];
    NSDictionary *report = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    NSString *callback = [NSString stringWithUTF8String:callbackURL];
    return [report isKindOfClass:[NSDictionary class]] && callback.length &&
        SHDWRunnerSendReport(report, callback) ? 1 : 0;
}
