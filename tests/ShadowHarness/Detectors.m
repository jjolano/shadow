#import "Detectors.h"
#import "Battery.h"
#import "DetectorDashboard.h"
#import "SHDWEmbeddedSwift.h"

#import <Shadow.h>
#import <UIKit/UIKit.h>
#import <unistd.h>

extern BOOL SHDWDyldProbeWriteDashboardReport(NSString **failure);
extern NSDictionary *SHDWEmbeddedRunDetector(NSString *identifier);

static NSString * const kSHDWResultsDirectory = @"/var/mobile/Documents/ShadowDetectorTests";

// Embedded engine: every detector runs sequentially in-process on a serial
// worker queue, writing its report straight to the results directory. No
// app flips, no URL schemes, no TCP. dyldprobe was already embedded; the
// other twelve moved in via SHDWEmbedded.m + EmbeddedDrivers.swift.
static BOOL gSHDWRunning = NO;
static BOOL gSHDWRunAll = NO;
static NSUInteger gSHDWRunAllIndex = 0;
static NSString *gSHDWIdentifier;
// Identifier currently executing within a Run All pass; nil between detectors
// and when no pass is active. Drives per-row settling in the dashboard.
static NSString *gSHDWRunAllCurrent;
// Watchdog generation: SHDWFinishCurrent only advances the chain for the
// run it was armed for. A late driver finish or stale timer for an older
// generation is ignored (its report, if any, is already on disk).
static NSUInteger gSHDWGeneration = 0;
static dispatch_block_t gSHDWRunAllCompletion;
static dispatch_queue_t gSHDWEmbeddedQueue;

static NSArray<NSString *> *SHDWDetectorIDs(void) {
    return @[
        @"dyldprobe", @"iossecuritysuite", @"jailbreakdetector", @"securitytoolkit",
        @"dttjailbreakdetection", @"freerasp", @"roothider", @"batjailbreakguard",
        @"safetynet", @"devicesecuritykit", @"jailmonkey",
        @"isjailbroken", @"swiftyjbd",
    ];
}

static BOOL SHDWKnowsDetector(NSString *identifier) {
    return [SHDWDetectorIDs() containsObject:identifier];
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
            @"phase": @"embedded",
            @"clean": @NO,
            @"checks": @[@{
                @"id": @"embedded.run",
                @"name": @"Embedded run",
                @"passed": @NO,
                @"message": message ?: @"Detector did not return a report",
            }],
        }],
    });
}

static void SHDWRunNextDetector(void);

static void SHDWFinishCurrentGen(BOOL success, NSString *identifier, NSString *message, NSUInteger generation) {
    if (generation != gSHDWGeneration) return;
    BOOL runningAll = gSHDWRunAll;
    gSHDWIdentifier = nil;
    gSHDWRunAllCurrent = nil;
    gSHDWRunning = NO;
    if (!success && identifier.length) SHDWWriteFailure(identifier, message);
    SHDWNotifyResults();

    if (runningAll) {
        SHDWRunNextDetector();
    }
}



// One detector, synchronously, on the worker queue. dyldprobe keeps its
// existing entry point; everything else goes through the embedded drivers.
// A per-detector watchdog (FreeRASP needs ~35s) writes an error report if
// the driver hangs instead of stalling the chain forever.
static void SHDWRunEmbeddedGen(NSString *identifier, NSUInteger generation) {
    uint64_t start = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
    // Progress marker FIRST: proves the chain reached this detector even if
    // the driver never returns (hang/crash). The driver overwrites it with
    // the real report on success.
    SHDWWriteReport(identifier, @{
        @"schemaVersion": @1,
        @"sdk": @{ @"id": identifier, @"name": identifier, @"version": @"unknown" },
        @"outcome": @"error",
        @"generatedAt": [NSISO8601DateFormatter.new stringFromDate:[NSDate date]],
        @"rounds": @[@{
            @"phase": @"embedded",
            @"clean": @NO,
            @"checks": @[@{
                @"id": @"embedded.started",
                @"name": @"Embedded run",
                @"passed": @NO,
                @"message": @"Detector started, no result yet",
            }],
        }],
    });
    NSDictionary *report = nil;
    if ([identifier isEqualToString:@"dyldprobe"]) {
        NSString *failure = nil;
        BOOL success = SHDWDyldProbeWriteDashboardReport(&failure);
        if (!success) {
            SHDWFinishCurrentGen(NO, identifier, failure ?: @"Embedded dyldprobe failed", generation);
            return;
        }
        // dyldprobe persists its own report; nothing more to write.
        SHDWFinishCurrentGen(YES, identifier, nil, generation);
        return;
    }
    @try {
        report = SHDWEmbeddedRunDetector(identifier);
    } @catch (NSException *e) {
        report = nil;
    }
    uint64_t elapsed = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) - start;
    if (generation != gSHDWGeneration) return;
    if (![report isKindOfClass:[NSDictionary class]]) {
        SHDWFinishCurrentGen(NO, identifier, @"Detector did not return a report", generation);
        return;
    }
    NSMutableDictionary *stamped = [report mutableCopy];
    NSMutableDictionary *timing = [[report[@"timing"] isKindOfClass:[NSDictionary class]]
        ? report[@"timing"] : @{} mutableCopy];
    timing[@"elapsed_ns"] = @(elapsed);
    stamped[@"timing"] = timing;
    if (!SHDWWriteReport(identifier, stamped)) {
        SHDWFinishCurrentGen(NO, identifier, @"Cannot persist detector report", generation);
        return;
    }
    SHDWFinishCurrentGen(YES, identifier, nil, generation);
}

static BOOL SHDWStartDetector(NSString *identifier) {
    // NOTE: no gSHDWRunning re-entrancy gate. The watchdog below can fire
    // while a hung driver still occupies the worker queue; the chain must
    // still advance. Serialization comes from the serial queue + the
    // watchdog generation check, not from this flag.
    if (!SHDWKnowsDetector(identifier)) return NO;
    if (!gSHDWEmbeddedQueue) {
        gSHDWEmbeddedQueue = dispatch_queue_create(
            "me.jjolano.shadow.detector-embedded", DISPATCH_QUEUE_SERIAL);
    }
    gSHDWIdentifier = [identifier copy];
    gSHDWRunning = YES;
    SHDWNotifyResults();
    NSString *current = [identifier copy];
    NSUInteger generation = ++gSHDWGeneration;
    dispatch_async(gSHDWEmbeddedQueue, ^{
        SHDWRunEmbeddedGen(current, generation);
    });
    // Watchdog: FreeRASP settles ~30s; nothing should exceed 120s. On
    // timeout the chain records an error and moves on — a hung detector
    // must not stall the other eleven. The driver itself is synchronous
    // and cannot be cancelled; the generation check keeps a late finish
    // from double-advancing (SHDWFinishCurrent is idempotent per run:
    // gSHDWRunning is already NO).
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(120 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        SHDWFinishCurrentGen(NO, current, @"Detector timed out", generation);
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
    gSHDWRunAllCurrent = [identifier copy];
    if (!SHDWStartDetector(identifier)) {
        SHDWWriteFailure(identifier, @"Detector could not be started");
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
    if (gSHDWRunAll || gSHDWRunning || !SHDWKnowsDetector(identifier)) return NO;
    return SHDWStartDetector(identifier);
}

NSArray<NSString *> *SHDWAllDetectorIDs(void) {
    return SHDWDetectorIDs();
}

BOOL SHDWAllDetectorsRunning(void) {
    return gSHDWRunAll || gSHDWRunning;
}

SHDWDetectorPassState SHDWDetectorRunAllState(NSString *identifier) {
    if (!gSHDWRunAll) return SHDWDetectorPassIdle;
    if ([identifier isEqualToString:gSHDWRunAllCurrent]) return SHDWDetectorPassRunning;
    // gSHDWRunAllIndex points at the NEXT detector to start; everything before
    // the current one has already produced its report, everything after is
    // queued. Find this detector's slot and compare against the frontier.
    NSArray<NSString *> *ids = SHDWDetectorIDs();
    NSUInteger slot = [ids indexOfObject:identifier];
    if (slot == NSNotFound) return SHDWDetectorPassIdle;
    NSUInteger current = gSHDWRunAllCurrent ? [ids indexOfObject:gSHDWRunAllCurrent] : gSHDWRunAllIndex;
    return slot < current ? SHDWDetectorPassDone : SHDWDetectorPassPending;
}
