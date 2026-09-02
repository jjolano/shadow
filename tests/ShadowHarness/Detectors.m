#import "Detectors.h"
#import "Battery.h"
#import "DetectorDashboard.h"

#import <Shadow.h>
#import <UIKit/UIKit.h>

#import <arpa/inet.h>
#import <errno.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import <unistd.h>

extern BOOL SHDWDyldProbeWriteDashboardReport(NSString **failure);

static NSString * const kSHDWResultsDirectory = @"/var/mobile/Documents/ShadowDetectorTests";
static const NSUInteger kSHDWMaxEnvelopeBytes = 8 * 1024 * 1024;

static NSArray<NSString *> *SHDWDetectorIDs(void) {
    return @[
        @"dyldprobe", @"iossecuritysuite", @"jailbreakdetector", @"securitytoolkit",
        @"dttjailbreakdetection", @"freerasp", @"roothider", @"batjailbreakguard",
        @"safetynet", @"devicesecuritykit", @"jailmonkey",
    ];
}

static NSDictionary *SHDWRunnerForID(NSString *identifier) {
    static NSDictionary *runners;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        runners = @{
            @"dyldprobe": @{ @"scheme": @"shadow-dyldprobe", @"bundle": @"me.jjolano.dyldprobe" },
            @"iossecuritysuite": @{ @"scheme": @"shadow-detector-iossecuritysuite", @"bundle": @"me.jjolano.shadow.test.iossecuritysuite" },
            @"jailbreakdetector": @{ @"scheme": @"shadow-detector-jailbreakdetector", @"bundle": @"me.jjolano.shadow.test.jailbreakdetector" },
            @"securitytoolkit": @{ @"scheme": @"shadow-detector-securitytoolkit", @"bundle": @"me.jjolano.shadow.test.securitytoolkit" },
            @"dttjailbreakdetection": @{ @"scheme": @"shadow-detector-dtt", @"bundle": @"me.jjolano.shadow.test.dtt" },
            @"freerasp": @{ @"scheme": @"shadow-detector-freerasp", @"bundle": @"me.jjolano.shadow.test.freerasp" },
            @"roothider": @{ @"scheme": @"shadow-detector-roothider", @"bundle": @"me.jjolano.shadow.test.roothider" },
            @"batjailbreakguard": @{ @"scheme": @"shadow-detector-bat", @"bundle": @"me.jjolano.shadow.test.bat" },
            @"safetynet": @{ @"scheme": @"shadow-detector-safetynet", @"bundle": @"me.jjolano.shadow.test.safetynet" },
            @"devicesecuritykit": @{ @"scheme": @"shadow-detector-dsk", @"bundle": @"me.jjolano.shadow.test.devicesecuritykit" },
            @"jailmonkey": @{ @"scheme": @"shadow-detector-jailmonkey", @"bundle": @"me.jjolano.shadow.test.jailmonkey" },
        };
    });
    return runners[identifier];
}

static NSString *SHDWQueryEscape(NSString *value) {
    NSMutableCharacterSet *allowed = [[NSCharacterSet alphanumericCharacterSet] mutableCopy];
    [allowed addCharactersInString:@"-._~"];
    return [value stringByAddingPercentEncodingWithAllowedCharacters:allowed] ?: @"";
}

static BOOL SHDWReadFully(int fd, void *buffer, size_t length) {
    uint8_t *cursor = buffer;
    while (length) {
        ssize_t received = recv(fd, cursor, length, 0);
        if (received <= 0) return NO;
        cursor += received;
        length -= (size_t)received;
    }
    return YES;
}

static int gSHDWListener = -1;
static uint16_t gSHDWPort = 0;
static NSString *gSHDWIdentifier;
static NSString *gSHDWNonce;
static BOOL gSHDWRunning = NO;
static BOOL gSHDWRunAll = NO;
static NSUInteger gSHDWRunAllIndex = 0;
static dispatch_block_t gSHDWRunAllCompletion;
static dispatch_queue_t gSHDWTransportQueue;

static void SHDWCloseListener(void) {
    int listener = gSHDWListener;
    gSHDWListener = -1;
    gSHDWPort = 0;
    if (listener >= 0) close(listener);
}

static void SHDWNotifyResults(void) {
    [[NSNotificationCenter defaultCenter] postNotificationName:SHDWDetectorResultsChanged object:nil];
}

static BOOL SHDWWriteReport(NSString *identifier, NSDictionary *report) {
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:&error];
    if (!data) return NO;
    NSString *path = [kSHDWResultsDirectory stringByAppendingPathComponent:
        [identifier stringByAppendingPathExtension:@"json"]];
    __block BOOL written = NO;
    SHADOW_INTERNAL_SCOPE {
        [[NSFileManager defaultManager] createDirectoryAtPath:kSHDWResultsDirectory
            withIntermediateDirectories:YES attributes:nil error:nil];
        written = ShdwWriteEvidenceData(data, path);
    }
    return written;
}

static void SHDWWriteFailure(NSString *identifier, NSString *message) {
    SHDWWriteReport(identifier, @{
        @"schemaVersion": @1,
        @"sdk": @{ @"id": identifier, @"name": identifier, @"version": @"unknown" },
        @"outcome": @"error",
        @"generatedAt": [NSISO8601DateFormatter.new stringFromDate:[NSDate date]],
        @"rounds": @[@{
            @"phase": @"transport",
            @"clean": @NO,
            @"checks": @[@{
                @"id": @"runner.transport",
                @"name": @"Runner transport",
                @"passed": @NO,
                @"message": message ?: @"Runner did not return a report",
            }],
        }],
    });
}

static void SHDWRunNextDetector(void);

static void SHDWFinishCurrent(BOOL success, NSString *message) {
    NSString *identifier = gSHDWIdentifier;
    BOOL runningAll = gSHDWRunAll;
    SHDWCloseListener();
    gSHDWIdentifier = nil;
    gSHDWNonce = nil;
    gSHDWRunning = NO;
    if (!success && identifier.length) SHDWWriteFailure(identifier, message);
    SHDWNotifyResults();

    if (runningAll) {
        dispatch_async(dispatch_get_main_queue(), ^{
            SHDWRunNextDetector();
        });
    }
}

static void SHDWHandleEnvelope(NSData *data, NSString *identifier, NSString *nonce) {
    if (!data.length) {
        SHDWFinishCurrent(NO, @"Runner callback returned no data");
        return;
    }

    NSError *error = nil;
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    NSDictionary *envelope = [object isKindOfClass:[NSDictionary class]] ? object : nil;
    NSDictionary *report = [envelope[@"report"] isKindOfClass:[NSDictionary class]] ? envelope[@"report"] : nil;
    NSDictionary *sdk = [report[@"sdk"] isKindOfClass:[NSDictionary class]] ? report[@"sdk"] : nil;
    BOOL valid = envelope && [envelope[@"nonce"] isEqual:nonce] &&
        [envelope[@"identifier"] isEqual:identifier] &&
        [sdk[@"id"] isEqual:identifier] && [report[@"rounds"] isKindOfClass:[NSArray class]];
    if (!valid) {
        SHDWFinishCurrent(NO, error.localizedDescription ?: @"Invalid runner callback");
        return;
    }

    if (SHDWWriteReport(identifier, report)) {
        SHDWFinishCurrent(YES, nil);
    } else {
        SHDWFinishCurrent(NO, @"Cannot persist runner report");
    }
}

static void SHDWAcceptCallback(NSString *identifier, NSString *nonce) {
    int listener = gSHDWListener;
    if (listener < 0) return;
    if (!gSHDWTransportQueue) gSHDWTransportQueue = dispatch_queue_create("me.jjolano.shadow.detector-transport", DISPATCH_QUEUE_SERIAL);
    dispatch_async(gSHDWTransportQueue, ^{
        struct sockaddr_in address = {0};
        socklen_t addressLength = sizeof(address);
        int client = accept(listener, (struct sockaddr *)&address, &addressLength);
        if (client < 0) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (gSHDWRunning && [gSHDWNonce isEqual:nonce]) SHDWFinishCurrent(NO, @"Runner callback connection failed");
            });
            return;
        }
        struct timeval timeout = {10, 0};
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        uint32_t networkLength = 0;
        BOOL complete = SHDWReadFully(client, &networkLength, sizeof(networkLength));
        uint32_t length = ntohl(networkLength);
        NSMutableData *data = nil;
        if (complete && length > 0 && length <= kSHDWMaxEnvelopeBytes) {
            data = [NSMutableData dataWithLength:length];
            complete = SHDWReadFully(client, data.mutableBytes, length);
        } else {
            complete = NO;
        }
        shutdown(client, SHUT_RDWR);
        close(client);
        if (!complete || !data.length) {
            // RASP port checks connect and close without sending a callback.
            // Keep the listener alive for the runner's real framed envelope.
            dispatch_async(dispatch_get_main_queue(), ^{
                if (gSHDWRunning && [gSHDWNonce isEqual:nonce]) {
                    SHDWAcceptCallback(identifier, nonce);
                }
            });
            return;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!gSHDWRunning || ![gSHDWNonce isEqual:nonce]) return;
            SHDWHandleEnvelope(data, identifier, nonce);
        });
    });
}

static BOOL SHDWStartListener(NSString *identifier, NSString **callbackURL) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return NO;
    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in address = {0};
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(listener, 1) != 0) {
        close(listener);
        return NO;
    }
    socklen_t addressLength = sizeof(address);
    if (getsockname(listener, (struct sockaddr *)&address, &addressLength) != 0) {
        close(listener);
        return NO;
    }
    NSString *nonce = NSUUID.UUID.UUIDString.lowercaseString;
    gSHDWListener = listener;
    gSHDWPort = ntohs(address.sin_port);
    gSHDWIdentifier = [identifier copy];
    gSHDWNonce = nonce;
    gSHDWRunning = YES;
    if (callbackURL) {
        *callbackURL = [NSString stringWithFormat:@"shdw-tcp://127.0.0.1:%u/result?nonce=%@",
            gSHDWPort, SHDWQueryEscape(nonce)];
    }
    SHDWAcceptCallback(identifier, nonce);
    return YES;
}

static void SHDWRunnerLaunchFailed(NSString *nonce, NSString *message) {
    if (gSHDWRunning && [gSHDWNonce isEqual:nonce]) SHDWFinishCurrent(NO, message);
}

static BOOL SHDWStartEmbeddedDyldProbe(void) {
    if (gSHDWRunning) return NO;
    gSHDWIdentifier = @"dyldprobe";
    gSHDWNonce = NSUUID.UUID.UUIDString.lowercaseString;
    gSHDWRunning = YES;
    NSString *nonce = [gSHDWNonce copy];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *failure = nil;
        BOOL success = SHDWDyldProbeWriteDashboardReport(&failure);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!gSHDWRunning || ![gSHDWNonce isEqual:nonce]) return;
            SHDWFinishCurrent(success, failure ?: @"Embedded dyldprobe failed");
        });
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(90 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (gSHDWRunning && [gSHDWNonce isEqual:nonce])
            SHDWFinishCurrent(NO, @"Embedded dyldprobe timed out");
    });
    return YES;
}

static BOOL SHDWStartDetector(NSString *identifier) {
    if ([identifier isEqualToString:@"dyldprobe"]) return SHDWStartEmbeddedDyldProbe();
    NSDictionary *runner = SHDWRunnerForID(identifier);
    NSString *scheme = runner[@"scheme"];
    if (!scheme.length || gSHDWRunning) return NO;

    NSString *callback = nil;
    if (!SHDWStartListener(identifier, &callback)) return NO;
    NSString *nonce = [gSHDWNonce copy];
    NSString *urlString = [NSString stringWithFormat:@"%@://run?nonce=%@&callback=%@",
        scheme, SHDWQueryEscape(nonce), SHDWQueryEscape(callback)];
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) {
        SHDWRunnerLaunchFailed(nonce, @"Runner URL could not be constructed");
        return NO;
    }
    [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:^(BOOL success) {
        if (!success) {
            dispatch_async(dispatch_get_main_queue(), ^{
                SHDWRunnerLaunchFailed(nonce, @"Runner application is not installed or did not accept its URL");
            });
        }
    }];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(90 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        SHDWRunnerLaunchFailed(nonce, @"Runner callback timed out");
    });
    return YES;
}

static void SHDWRunNextDetector(void) {
    NSArray *identifiers = SHDWDetectorIDs();
    if (gSHDWRunAllIndex >= identifiers.count) {
        gSHDWRunAll = NO;
        dispatch_block_t completion = gSHDWRunAllCompletion;
        gSHDWRunAllCompletion = nil;
        SHDWNotifyResults();
        if (completion) completion();
        return;
    }
    NSString *identifier = identifiers[gSHDWRunAllIndex++];
    if (!SHDWStartDetector(identifier)) {
        SHDWWriteFailure(identifier, @"Runner could not be started");
        SHDWNotifyResults();
        dispatch_async(dispatch_get_main_queue(), ^{
            SHDWRunNextDetector();
        });
    }
}

void SHDWRunAllDetectors(void) {
    SHDWRunAllDetectorsWithCompletion(nil);
}

void SHDWRunAllDetectorsWithCompletion(dispatch_block_t completion) {
    if (gSHDWRunAll || gSHDWRunning) return;
    gSHDWRunAll = YES;
    gSHDWRunAllIndex = 0;
    gSHDWRunAllCompletion = [completion copy];
    SHDWNotifyResults();
    SHDWRunNextDetector();
}

BOOL SHDWRunDetectorWithID(NSString *identifier) {
    if (gSHDWRunAll || gSHDWRunning || !SHDWRunnerForID(identifier)) return NO;
    return SHDWStartDetector(identifier);
}

NSArray<NSString *> *SHDWAllDetectorIDs(void) {
    return SHDWDetectorIDs();
}

BOOL SHDWAllDetectorsRunning(void) {
    return gSHDWRunAll || gSHDWRunning;
}
