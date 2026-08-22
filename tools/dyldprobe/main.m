#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <mach/task_info.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <errno.h>
#import <stdatomic.h>
#import <stdio.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

static uint64_t gProbeStartTicks = 0;
static mach_timebase_info_data_t gProbeTimebase = {0, 0};

__attribute__((constructor)) static void probe_clock_start(void) {
    gProbeStartTicks = mach_continuous_time();
    mach_timebase_info(&gProbeTimebase);
}

static uint64_t probe_elapsed_ns(uint64_t end) {
    if(!gProbeStartTicks || !gProbeTimebase.denom || end < gProbeStartTicks) return 0;
    uint64_t ticks = end - gProbeStartTicks;
    return (ticks / gProbeTimebase.denom) * gProbeTimebase.numer +
        ((ticks % gProbeTimebase.denom) * gProbeTimebase.numer) / gProbeTimebase.denom;
}

// dyldprobe — on-device verification probe for Shadow.
// Shows the jailbreak the way detectors see it, from four angles:
//   1. dyld_all_image_infos read DIRECTLY from memory (W2's target)
//   2. the dyld API view (_dyld_image_count / _dyld_get_image_name)
//   3. file-existence probes of known jailbreak paths
//   4. URL scheme probes (canOpenURL)
// Plus W2-specific checks appended as sections 5-7: dladdr on addresses
// taken from the direct infoArray read + independent dlsym probes of hidden
// images' symbols, add/remove-image stress against the direct infoArray
// read using a dedicated unloadable on-disk dylib (with a concurrent direct-
// memory reader thread), and uuid / infoArrayChangeTimestamp invariants.
// Run it with Shadow disabled for this app (baseline), then with Shadow
// enabled and all hooks on — the two reports are the test.

// Section 8 helpers: the fishhook rebinding shape IOSSecuritySuite's
// denyFishHook uses, and the dummy replacement it points "dladdr" at.
// A successful revert makes every later dladdr call hit this dummy's 0
// ("no info"), which is exactly what the section detects.
struct rebinding {
    char* name;
    void* replacement;
    void** replaced;
};

static int dyldprobe_dummy_dladdr(const void* addr, Dl_info* info) {
    return 0;
}

// Forward decl: section 8 probes ProbeReport's own address.
static NSString* ProbeReport(void);

static BOOL probe_is_foreign_image(NSString* p, NSString* appPath) {
    return ![p hasPrefix:@"/System"] && ![p hasPrefix:appPath];
}

typedef struct {
    kern_return_t result;
    mach_msg_type_number_t count;
    task_dyld_info_data_t taskInfo;
    struct dyld_all_image_infos* infos;
    unsigned retries;
    BOOL valid;
} ProbeTaskDyldInfo;

static ProbeTaskDyldInfo probe_task_dyld_info(void) {
    ProbeTaskDyldInfo probe = {0};
    probe.count = TASK_DYLD_INFO_COUNT;
    probe.result = task_info(mach_task_self(), TASK_DYLD_INFO,
        (task_info_t)&probe.taskInfo, &probe.count);
    if(probe.result != KERN_SUCCESS || probe.count < TASK_DYLD_INFO_COUNT ||
       probe.taskInfo.all_image_info_addr == 0 ||
       probe.taskInfo.all_image_info_size < sizeof(struct dyld_all_image_infos) ||
       probe.taskInfo.all_image_info_format != TASK_DYLD_ALL_IMAGE_INFO_64) {
        return probe;
    }
    probe.infos = (struct dyld_all_image_infos*)(uintptr_t)probe.taskInfo.all_image_info_addr;
    for(probe.retries = 0; probe.retries < 4 && !probe.infos->infoArray; probe.retries++) {
        usleep(1000);
    }
    probe.valid = probe.infos->infoArray != NULL;
    return probe;
}

static struct dyld_all_image_infos* probe_direct_infos(void) {
    ProbeTaskDyldInfo probe = probe_task_dyld_info();
    return probe.valid ? probe.infos : NULL;
}

static NSArray<NSString*>* probe_hidden_markers(void) {
    return @[
        @"/var/jb", @"libhooker", @"libsubstitute", @"libsubstrate",
        @"libellekit", @"MobileSubstrate", @"pspawn_payload", @"tweakloader",
        @"ShadowCore", @"Shadow.dylib", @"Shadow.framework", @"HookKit", @"libSandy"
    ];
}

static NSArray<NSString*>* probe_hidden_images(const struct dyld_image_info* images,
                                               uint32_t count,
                                               NSString* appPath) {
    NSMutableArray<NSString*>* hidden = [NSMutableArray new];
    NSArray<NSString*>* markers = probe_hidden_markers();
    for(uint32_t i = 0; images && i < count; i++) {
        NSString* path = images[i].imageFilePath ? @(images[i].imageFilePath) : @"";
        if([path hasPrefix:appPath]) {
            continue;
        }
        for(NSString* marker in markers) {
            if([path containsString:marker]) {
                [hidden addObject:path];
                break;
            }
        }
    }
    return hidden;
}

static NSArray<NSString*>* probe_public_hidden_images(NSString* appPath) {
    NSMutableArray<NSString*>* hidden = [NSMutableArray new];
    NSArray<NSString*>* markers = probe_hidden_markers();
    uint32_t count = _dyld_image_count();
    for(uint32_t i = 0; i < count; i++) {
        const char* name = _dyld_get_image_name(i);
        NSString* path = name ? @(name) : @"";
        if([path hasPrefix:appPath]) {
            continue;
        }
        for(NSString* marker in markers) {
            if([path containsString:marker]) {
                [hidden addObject:path];
                break;
            }
        }
    }
    return hidden;
}

static NSString* probe_documents_directory(void) {
    const char* home = getenv("CFFIXED_USER_HOME");
    if(!home || home[0] != '/') home = getenv("HOME");
    return home && home[0] == '/' ?
        [[NSString stringWithUTF8String:home] stringByAppendingPathComponent:@"Documents"] : nil;
}

static NSDictionary* probe_launch_context(NSString* documents) {
    NSData* data = documents ? [NSData dataWithContentsOfFile:
        [documents stringByAppendingPathComponent:@".ShadowStealthContext.json"]] : nil;
    id context = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
    return [context isKindOfClass:[NSDictionary class]] ? context : nil;
}

static BOOL probe_paths_match(NSString* expected, const char* actual) {
    if(!expected || !actual) return NO;
    const char* expectedPath = expected.fileSystemRepresentation;
    if(!expectedPath) return NO;
    if(strcmp(expectedPath, actual) == 0) return YES;

    // dyld canonicalizes container paths through /private while app code
    // commonly receives the /var alias. Avoid realpath here: this probe
    // intentionally runs beneath filesystem hooks and needs no I/O to compare
    // the two spellings of the same kernel path.
    if(strncmp(expectedPath, "/var/", 5) == 0 && strncmp(actual, "/private/var/", 13) == 0) {
        return strcmp(expectedPath, actual + sizeof("/private") - 1) == 0;
    }
    if(strncmp(expectedPath, "/private/var/", 13) == 0 && strncmp(actual, "/var/", 5) == 0) {
        return strcmp(expectedPath + sizeof("/private") - 1, actual) == 0;
    }
    return NO;
}

// The public dyld registration APIs deliberately have no eight-callback
// ceiling.  Keep distinct callbacks here so a capped interposer cannot make
// one callback look like nine registrations.
enum { PROBE_DYLD_CALLBACK_COUNT = 9 };
static _Atomic(uint32_t) gProbeDyldReplay[PROBE_DYLD_CALLBACK_COUNT];
static _Atomic(uint32_t) gProbeDyldAdd[PROBE_DYLD_CALLBACK_COUNT];
static _Atomic(uint32_t) gProbeDyldRemove[PROBE_DYLD_CALLBACK_COUNT];
static _Atomic(uint32_t) gProbeDyldExpectedReplay[PROBE_DYLD_CALLBACK_COUNT];
static _Atomic(bool) gProbeDyldEventsArmed = false;
static dispatch_once_t gProbeDyldCallbacksOnce;

#define PROBE_DYLD_CALLBACK(index) \
static void probe_dyld_add_##index(const struct mach_header* mh, intptr_t slide) { \
    (void)mh; (void)slide; \
    if(atomic_load_explicit(&gProbeDyldEventsArmed, memory_order_relaxed)) { \
        atomic_fetch_add_explicit(&gProbeDyldAdd[index], 1, memory_order_relaxed); \
    } else { \
        atomic_fetch_add_explicit(&gProbeDyldReplay[index], 1, memory_order_relaxed); \
    } \
} \
static void probe_dyld_remove_##index(const struct mach_header* mh, intptr_t slide) { \
    (void)mh; (void)slide; \
    atomic_fetch_add_explicit(&gProbeDyldRemove[index], 1, memory_order_relaxed); \
}

PROBE_DYLD_CALLBACK(0)
PROBE_DYLD_CALLBACK(1)
PROBE_DYLD_CALLBACK(2)
PROBE_DYLD_CALLBACK(3)
PROBE_DYLD_CALLBACK(4)
PROBE_DYLD_CALLBACK(5)
PROBE_DYLD_CALLBACK(6)
PROBE_DYLD_CALLBACK(7)
PROBE_DYLD_CALLBACK(8)

static void (*const kProbeDyldAddCallbacks[PROBE_DYLD_CALLBACK_COUNT])(
    const struct mach_header*, intptr_t) = {
    probe_dyld_add_0, probe_dyld_add_1, probe_dyld_add_2,
    probe_dyld_add_3, probe_dyld_add_4, probe_dyld_add_5,
    probe_dyld_add_6, probe_dyld_add_7, probe_dyld_add_8,
};
static void (*const kProbeDyldRemoveCallbacks[PROBE_DYLD_CALLBACK_COUNT])(
    const struct mach_header*, intptr_t) = {
    probe_dyld_remove_0, probe_dyld_remove_1, probe_dyld_remove_2,
    probe_dyld_remove_3, probe_dyld_remove_4, probe_dyld_remove_5,
    probe_dyld_remove_6, probe_dyld_remove_7, probe_dyld_remove_8,
};

static void probe_install_dyld_callbacks(void) {
    dispatch_once(&gProbeDyldCallbacksOnce, ^{
        atomic_store_explicit(&gProbeDyldEventsArmed, false, memory_order_relaxed);
        for(uint32_t i = 0; i < PROBE_DYLD_CALLBACK_COUNT; i++) {
            atomic_store_explicit(&gProbeDyldExpectedReplay[i], _dyld_image_count(), memory_order_relaxed);
            _dyld_register_func_for_add_image(kProbeDyldAddCallbacks[i]);
            _dyld_register_func_for_remove_image(kProbeDyldRemoveCallbacks[i]);
        }
        atomic_store_explicit(&gProbeDyldEventsArmed, true, memory_order_relaxed);
    });
}

static NSArray<NSDictionary*>* probe_dyld_callback_rows(
    const uint32_t addBefore[PROBE_DYLD_CALLBACK_COUNT],
    const uint32_t removeBefore[PROBE_DYLD_CALLBACK_COUNT]) {
    NSMutableArray<NSDictionary*>* rows = [NSMutableArray new];
    for(uint32_t i = 0; i < PROBE_DYLD_CALLBACK_COUNT; i++) {
        uint32_t replay = atomic_load_explicit(&gProbeDyldReplay[i], memory_order_relaxed);
        uint32_t add = atomic_load_explicit(&gProbeDyldAdd[i], memory_order_relaxed);
        uint32_t remove = atomic_load_explicit(&gProbeDyldRemove[i], memory_order_relaxed);
        uint32_t expectedReplay = atomic_load_explicit(&gProbeDyldExpectedReplay[i], memory_order_relaxed);
        BOOL passed = replay == expectedReplay && add > addBefore[i] && remove > removeBefore[i];
        [rows addObject:@{
            @"id" : @(i + 1), @"expected_existing_images" : @(expectedReplay),
            @"existing_image_replay" : @(replay),
            @"later_add" : @(add - addBefore[i]),
            @"later_remove" : @(remove - removeBefore[i]),
            @"status" : passed ? @"PASS" : @"FAIL",
        }];
    }
    return rows;
}

static NSString* probe_stage_dyld_stress_library(NSFileManager* fm, NSString** failure) {
    NSString* documents = probe_documents_directory();
    if(!documents) {
        if(failure) *failure = @"container Documents directory unavailable";
        return nil;
    }

    NSString* source = nil;
    NSString* supplied = probe_launch_context(documents)[@"dyld_stress_library"];
    NSString* suppliedPrefix = [documents stringByAppendingString:@"/.ShadowDyldStress-"];
    if([supplied isKindOfClass:[NSString class]] && [supplied hasPrefix:suppliedPrefix] &&
       [supplied hasSuffix:@".dylib"] && [fm fileExistsAtPath:supplied]) {
        source = supplied;
    }
    for(NSString* name in @[@"libshdwtestlib.dylib", @"shdwtestlib.dylib"]) {
        if(source) break;
        NSString* candidate = [[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:name];
        if([fm fileExistsAtPath:candidate]) {
            source = candidate;
            break;
        }
    }
    if(!source) {
        if(failure) *failure = @"packaged shdwtestlib is missing";
        return nil;
    }

    NSString* staged = [documents stringByAppendingPathComponent:[NSString stringWithFormat:
        @".shadow-dyld-%@-%@", [[NSUUID UUID] UUIDString], [source lastPathComponent]]];
    NSError* error = nil;
    if(![fm copyItemAtPath:source toPath:staged error:&error]) {
        if(failure) *failure = [NSString stringWithFormat:@"cannot stage shdwtestlib: %@", error];
        return nil;
    }
    return staged;
}

static BOOL probe_direct_contains_path(ProbeTaskDyldInfo probe, NSString* path) {
    if(!probe.valid || !probe.infos->infoArray) return NO;
    for(uint32_t i = 0; i < probe.infos->infoArrayCount; i++) {
        const char* candidate = probe.infos->infoArray[i].imageFilePath;
        if(probe_paths_match(path, candidate)) return YES;
    }
    return NO;
}

static BOOL probe_direct_uuid_contains_path(ProbeTaskDyldInfo probe, NSString* path) {
    if(!probe.valid || !probe.infos->infoArray || !probe.infos->uuidArray) return NO;
    for(uint32_t i = 0; i < probe.infos->infoArrayCount; i++) {
        const struct dyld_image_info* image = &probe.infos->infoArray[i];
        if(!probe_paths_match(path, image->imageFilePath)) continue;
        for(uint32_t j = 0; j < probe.infos->uuidArrayCount; j++) {
            if(probe.infos->uuidArray[j].imageLoadAddress == image->imageLoadAddress) return YES;
        }
    }
    return NO;
}

static NSDictionary* probe_dyld_callback_contract(void) {
    probe_install_dyld_callbacks();
    uint32_t addBefore[PROBE_DYLD_CALLBACK_COUNT] = {0};
    uint32_t removeBefore[PROBE_DYLD_CALLBACK_COUNT] = {0};
    for(uint32_t i = 0; i < PROBE_DYLD_CALLBACK_COUNT; i++) {
        addBefore[i] = atomic_load_explicit(&gProbeDyldAdd[i], memory_order_relaxed);
        removeBefore[i] = atomic_load_explicit(&gProbeDyldRemove[i], memory_order_relaxed);
    }

    NSFileManager* fm = [NSFileManager defaultManager];
    NSString* stagingFailure = nil;
    NSString* stressPath = probe_stage_dyld_stress_library(fm, &stagingFailure);
    ProbeTaskDyldInfo base = probe_task_dyld_info();
    uint32_t baseCount = base.valid ? base.infos->infoArrayCount : 0;
    __block _Atomic(BOOL) readerStop = NO;
    __block uint32_t readerRuns = 0;
    __block uint32_t readerTorn = 0;
    __block uint32_t readerMax = 0;
    BOOL readerReady = NO;
    BOOL loaded = NO;
    BOOL unloaded = NO;
    BOOL markerOK = NO;
    BOOL uuidVisible = NO;

    if(stressPath && base.valid) {
        dispatch_queue_t readerQueue = dispatch_queue_create("dyldprobe.machine-reader", DISPATCH_QUEUE_SERIAL);
        dispatch_semaphore_t readerStarted = dispatch_semaphore_create(0);
        dispatch_async(readerQueue, ^{
            dispatch_semaphore_signal(readerStarted);
            while(!atomic_load_explicit(&readerStop, memory_order_relaxed)) {
                ProbeTaskDyldInfo sample = probe_task_dyld_info();
                if(!sample.valid || !sample.infos->infoArray || !sample.infos->infoArrayCount) {
                    usleep(1000);
                    continue;
                }
                uint32_t count = sample.infos->infoArrayCount;
                uint32_t cap = MIN(count, 8192u);
                uint32_t walked = 0;
                BOOL torn = NO;
                for(uint32_t i = 0; i < cap; i++) {
                    struct dyld_image_info info = sample.infos->infoArray[i];
                    if(!info.imageLoadAddress && !info.imageFilePath) {
                        torn = YES;
                        break;
                    }
                    walked++;
                }
                if(torn) readerTorn++;
                if(walked > readerMax) readerMax = walked;
                readerRuns++;
                usleep(1000);
            }
        });
        readerReady = dispatch_semaphore_wait(readerStarted,
            dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC)) == 0;

        loaded = YES;
        unloaded = YES;
        markerOK = YES;
        uuidVisible = YES;
        for(uint32_t i = 0; i < 8; i++) {
            void* handle = dlopen([stressPath fileSystemRepresentation], RTLD_NOW);
            if(!handle) {
                loaded = NO;
                unloaded = NO;
                markerOK = NO;
                break;
            }
            void* marker = dlsym(handle, "shdwtestlib_probe_marker");
            if(!marker) markerOK = NO;
            BOOL visible = NO, uuid = NO;
            for(uint32_t retry = 0; retry < 20; retry++) {
                ProbeTaskDyldInfo current = probe_task_dyld_info();
                visible = visible || probe_direct_contains_path(current, stressPath);
                uuid = uuid || probe_direct_uuid_contains_path(current, stressPath);
                if(visible && uuid) break;
                usleep(1000);
            }
            if(!visible) loaded = NO;
            if(!uuid) uuidVisible = NO;
            BOOL gone = dlclose(handle) == 0;
            for(uint32_t retry = 0; gone && retry < 20; retry++) {
                if(!probe_direct_contains_path(probe_task_dyld_info(), stressPath)) break;
                if(retry == 19) gone = NO;
                else usleep(1000);
            }
            if(!gone) unloaded = NO;
        }
        atomic_store_explicit(&readerStop, YES, memory_order_relaxed);
        dispatch_sync(readerQueue, ^{});
    }

    if(stressPath) [fm removeItemAtPath:stressPath error:nil];
    NSArray<NSDictionary*>* callbacks = probe_dyld_callback_rows(addBefore, removeBefore);
    BOOL callbacksPassed = YES;
    for(NSDictionary* row in callbacks) {
        if(![row[@"status"] isEqual:@"PASS"]) callbacksPassed = NO;
    }
    BOOL concurrencyPassed = readerReady && readerRuns > 0 && readerTorn == 0 && readerMax <= baseCount + 1;
    BOOL passed = stressPath && base.valid && loaded && unloaded && markerOK && uuidVisible && callbacksPassed && concurrencyPassed;
    return @{
        @"status" : passed ? @"PASS" : @"FAIL",
        @"callbacks" : callbacks,
        @"concurrency" : @{
            @"status" : concurrencyPassed ? @"PASS" : @"FAIL",
            @"reader_started" : @(readerReady), @"runs" : @(readerRuns),
            @"torn_reads" : @(readerTorn), @"max_entries" : @(readerMax),
            @"expected_max_entries" : @(baseCount + 1),
        },
        @"stress" : @{
            @"status" : (stressPath && base.valid && loaded && unloaded && markerOK && uuidVisible) ? @"PASS" : @"FAIL",
            @"path" : stressPath ?: @"",
            @"setup_failure" : stagingFailure ?: @"",
            @"loaded" : @(loaded), @"unloaded" : @(unloaded), @"marker" : @(markerOK),
            @"uuid_visible" : @(uuidVisible),
        },
    };
}

static NSString* probe_pointer_string(const void* pointer) {
    return [NSString stringWithFormat:@"0x%llx", (unsigned long long)(uintptr_t)pointer];
}

static NSString* probe_uuid_string(const uint8_t uuid[16]) {
    return [NSString stringWithFormat:
        @"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
        uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]];
}

static NSArray<NSDictionary*>* probe_sorted_dyld_rows(NSArray<NSDictionary*>* rows) {
    return [rows sortedArrayUsingComparator:^NSComparisonResult(NSDictionary* left, NSDictionary* right) {
        NSString* leftKey = [NSString stringWithFormat:@"%@|%@", left[@"address"], left[@"path"]];
        NSString* rightKey = [NSString stringWithFormat:@"%@|%@", right[@"address"], right[@"path"]];
        return [leftKey compare:rightKey];
    }];
}

static NSDictionary* probe_normalized_dyld_views(ProbeTaskDyldInfo probe, BOOL* uuidConsistent) {
    NSMutableDictionary<NSString*, NSString*>* uuids = [NSMutableDictionary new];
    NSMutableArray<NSString*>* uuidOrphans = [NSMutableArray new];
    if(probe.valid && probe.infos->uuidArray) {
        for(uint32_t i = 0; i < probe.infos->uuidArrayCount; i++) {
            const struct dyld_uuid_info* entry = &probe.infos->uuidArray[i];
            uuids[probe_pointer_string(entry->imageLoadAddress)] = probe_uuid_string(entry->imageUUID);
        }
    }

    NSMutableDictionary<NSString*, NSString*>* publicSlides = [NSMutableDictionary new];
    NSMutableArray<NSDictionary*>* publicRows = [NSMutableArray new];
    for(uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header* header = _dyld_get_image_header(i);
        NSString* address = probe_pointer_string(header);
        NSString* slide = [NSString stringWithFormat:@"0x%llx",
            (unsigned long long)(uint64_t)_dyld_get_image_vmaddr_slide(i)];
        const char* path = _dyld_get_image_name(i);
        publicSlides[address] = slide;
        [publicRows addObject:@{
            @"path" : path ? @(path) : @"", @"address" : address, @"header" : address,
            @"slide" : slide, @"uuid" : uuids[address] ?: [NSNull null],
        }];
    }

    NSMutableArray<NSDictionary*>* memoryRows = [NSMutableArray new];
    if(probe.valid && probe.infos->infoArray) {
        for(uint32_t i = 0; i < probe.infos->infoArrayCount; i++) {
            struct dyld_image_info entry = probe.infos->infoArray[i];
            NSString* address = probe_pointer_string(entry.imageLoadAddress);
            [memoryRows addObject:@{
                @"path" : entry.imageFilePath ? @(entry.imageFilePath) : @"",
                @"address" : address, @"header" : address,
                @"slide" : publicSlides[address] ?: @"unknown",
                @"uuid" : uuids[address] ?: [NSNull null],
            }];
        }
    }

    NSArray<NSDictionary*>* sortedPublic = probe_sorted_dyld_rows(publicRows);
    NSArray<NSDictionary*>* sortedMemory = probe_sorted_dyld_rows(memoryRows);
    BOOL consistent = probe.valid && sortedPublic.count > 0 && sortedMemory.count > 0;
    if(probe.valid && probe.infos->uuidArrayCount && !probe.infos->uuidArray) consistent = NO;
    for(NSString* address in uuids) {
        if(!publicSlides[address]) {
            // dyld retains UUID records for removed non-shared-cache images.
            // They are useful crash-reporting history, not live image entries.
            [uuidOrphans addObject:address];
        }
    }
    if(uuidConsistent) *uuidConsistent = consistent;
    return @{@"public" : sortedPublic, @"memory" : sortedMemory,
             @"uuid_orphan_addresses" : uuidOrphans};
}

static BOOL probe_write_machine_report(NSString** failure) {
    if(failure) *failure = nil;
    NSString* documents = probe_documents_directory();
    NSDictionary* context = probe_launch_context(documents);
    if(!documents || ![context isKindOfClass:[NSDictionary class]]) {
        if(failure) *failure = @"launch context unavailable";
        return NO;
    }

    for(NSString* key in @[@"run_id", @"row_id", @"requested_mode", @"nonce", @"probe_revision"]) {
        if(![context[key] isKindOfClass:[NSString class]] || ![context[key] length]) {
            if(failure) *failure = [NSString stringWithFormat:@"launch context key invalid: %@", key];
            return NO;
        }
    }
    NSString* mode = context[@"requested_mode"];
    if(![mode isEqualToString:@"uninjected"] && ![mode isEqualToString:@"injected"]) {
        if(failure) *failure = @"launch context mode invalid";
        return NO;
    }

    NSDictionary* callbackContract = probe_dyld_callback_contract();
    ProbeTaskDyldInfo taskProbe = probe_task_dyld_info();
    vm_region_basic_info_data_64_t regionInfo = {0};
    mach_msg_type_number_t regionInfoCount = VM_REGION_BASIC_INFO_COUNT_64;
    vm_address_t regionAddress = (vm_address_t)(uintptr_t)taskProbe.infos;
    vm_size_t regionSize = 0;
    mach_port_t regionObject = MACH_PORT_NULL;
    kern_return_t regionResult = taskProbe.valid ? vm_region_64(mach_task_self(),
        &regionAddress, &regionSize, VM_REGION_BASIC_INFO_64,
        (vm_region_info_t)&regionInfo, &regionInfoCount, &regionObject) : KERN_INVALID_ADDRESS;
    if(regionObject != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), regionObject);
    NSString* appPath = [NSBundle mainBundle].bundlePath;
    NSArray<NSString*>* directHidden = taskProbe.valid ?
        probe_hidden_images(taskProbe.infos->infoArray, taskProbe.infos->infoArrayCount, appPath) : @[];
    NSArray<NSString*>* publicHidden = probe_public_hidden_images(appPath);
    void* publicSymbol = dlsym(RTLD_DEFAULT, "dyld_all_image_infos");
    BOOL uuidConsistent = NO;
    NSDictionary* views = probe_normalized_dyld_views(taskProbe, &uuidConsistent);
    BOOL viewsAgree = [views[@"public"] isEqualToArray:views[@"memory"]];
    BOOL addressUUIDPassed = taskProbe.valid && viewsAgree && uuidConsistent;
    NSDictionary* dyldTaskInfo = @{
        @"address" : @((unsigned long long)taskProbe.taskInfo.all_image_info_addr),
        @"size" : @((unsigned long long)taskProbe.taskInfo.all_image_info_size),
        @"format" : @(taskProbe.taskInfo.all_image_info_format),
        @"retry" : taskProbe.valid ? @"PASS" : @"FAIL",
        @"null_info_array_retries" : @(taskProbe.retries),
    };
    BOOL callbackContractPassed = [callbackContract[@"status"] isEqualToString:@"PASS"];
    BOOL dyldPassed = callbackContractPassed && addressUUIDPassed;

    struct stat canaryStat;
    errno = 0;
    int statResult = stat("/var/jb", &canaryStat);
    int statErrno = errno;
    BOOL injected = [mode isEqualToString:@"injected"];
    BOOL canaryPassed = statResult == -1 && statErrno == ENOENT;
    BOOL setupFailure = !taskProbe.valid || (injected && !canaryPassed);
    BOOL leaked = injected && (directHidden.count || publicHidden.count);
    NSInteger producerExit = setupFailure ? 2 : (leaked || !dyldPassed) ? 1 : 0;
    NSString* aggregate = setupFailure ? @"SETUP-FAIL" :
        ((leaked || !dyldPassed) ? @"FAIL" :
            (injected ? @"PASS" : @"CONTROL-INACTIVE"));
    id canary = injected ? @{
        @"status" : canaryPassed ? @"PASS" : @"FAIL",
        @"probe" : @"stat(/var/jb)",
        @"result" : @(statResult),
        @"errno" : @(statErrno),
    } : @"CONTROL-INACTIVE";

    uint64_t reportEnd = mach_continuous_time();
    NSDictionary* report = @{
        @"schema_version" : @1,
        @"producer" : @"dyldprobe",
        @"run_id" : context[@"run_id"],
        @"row_id" : context[@"row_id"],
        @"row_type" : @"jailbroken",
        @"requested_mode" : mode,
        @"nonce" : context[@"nonce"],
        @"probe_revision" : context[@"probe_revision"],
        @"canary" : canary,
        @"observations" : @{
            @"aggregate" : aggregate,
			@"dyld" : @{
                @"case_id" : @"dyld-fidelity-v1",
                @"views" : views,
                @"task_dyld_info" : dyldTaskInfo,
                @"callbacks" : callbackContract[@"callbacks"],
                @"concurrency" : callbackContract[@"concurrency"],
                @"address_uuid" : addressUUIDPassed ? @"PASS" : @"FAIL",
                @"views_agree" : @(viewsAgree),
                @"uuid_consistent" : @(uuidConsistent),
                @"uuid_entry_count" : @(taskProbe.valid ? taskProbe.infos->uuidArrayCount : 0),
                @"uuid_orphan_addresses" : views[@"uuid_orphan_addresses"],
                @"stress" : callbackContract[@"stress"],
                @"status" : dyldPassed ? @"PASS" : @"FAIL",
			},
			@"timing" : @{
				@"clock" : @"mach_continuous_time",
				@"start_ticks" : @(gProbeStartTicks), @"end_ticks" : @(reportEnd),
				@"probe_elapsed_ns" : @(probe_elapsed_ns(reportEnd)),
			},
            @"task_dyld_info" : @{
                @"kern_return" : @(taskProbe.result),
                @"count" : @(taskProbe.count),
                @"address" : [NSString stringWithFormat:@"0x%llx",
                    (unsigned long long)taskProbe.taskInfo.all_image_info_addr],
                @"info_array_address" : [NSString stringWithFormat:@"%p",
                    taskProbe.valid ? taskProbe.infos->infoArray : NULL],
                @"size" : @((unsigned long long)taskProbe.taskInfo.all_image_info_size),
                @"format" : @(taskProbe.taskInfo.all_image_info_format),
                @"null_info_array_retries" : @(taskProbe.retries),
                @"retry" : taskProbe.valid ? @"PASS" : @"FAIL",
                @"valid" : @(taskProbe.valid),
                @"region" : @{
                    @"kern_return" : @(regionResult),
                    @"protection" : @(regionInfo.protection),
                    @"max_protection" : @(regionInfo.max_protection),
                    @"size" : @((unsigned long long)regionSize),
                },
            },
            @"direct_memory_view" : @{
                @"image_count" : taskProbe.valid ? @(taskProbe.infos->infoArrayCount) : @0,
                @"hidden_images" : directHidden,
            },
            @"public_api_view" : @{
                @"image_count" : @(_dyld_image_count()),
                @"hidden_images" : publicHidden,
            },
            @"public_symbol_observation" : @{
                @"symbol" : @"dyld_all_image_infos",
                @"address" : [NSString stringWithFormat:@"%p", publicSymbol],
            },
        },
        @"producer_exit" : @(producerExit),
    };
    NSError* error = nil;
    NSData* data = [NSJSONSerialization dataWithJSONObject:report options:0 error:&error];
    NSString* path = [documents stringByAppendingPathComponent:
        [NSString stringWithFormat:@"dyldprobe-%@.json", context[@"nonce"]]];
    if(!data) {
        if(failure) *failure = [NSString stringWithFormat:@"report serialization failed: %@", error.localizedDescription ?: @"unknown"];
        return NO;
    }
    if(![data writeToFile:path options:NSDataWritingAtomic error:&error]) {
        if(failure) *failure = [NSString stringWithFormat:@"report write failed: %@", error.localizedDescription ?: @"unknown"];
        return NO;
    }
    return YES;
}

static void probe_section_1(NSMutableString* out, NSString* appPath) {
    [out appendString:@"== 1. TASK_DYLD_INFO direct memory read ==\n"];
    ProbeTaskDyldInfo taskProbe = probe_task_dyld_info();
    struct dyld_all_image_infos* infos = taskProbe.valid ? taskProbe.infos : NULL;
    void* publicSymbol = dlsym(RTLD_DEFAULT, "dyld_all_image_infos");
    [out appendFormat:@"task_info kr=%d count=%u addr=0x%llx size=%llu format=%d retries=%u valid=%@\n",
        taskProbe.result, taskProbe.count,
        (unsigned long long)taskProbe.taskInfo.all_image_info_addr,
        (unsigned long long)taskProbe.taskInfo.all_image_info_size,
        taskProbe.taskInfo.all_image_info_format, taskProbe.retries,
        taskProbe.valid ? @"YES" : @"NO"];
    [out appendFormat:@"public dlsym(dyld_all_image_infos) = %p\n", publicSymbol];

    if(infos && infos->infoArray) {
        [out appendFormat:@"infoArrayCount = %lu\n", (unsigned long)infos->infoArrayCount];
        [out appendFormat:@"uuidArrayCount = %lu\n", (unsigned long)infos->uuidArrayCount];
        [out appendString:@"non-system entries:\n"];

        for(uint32_t i = 0; i < infos->infoArrayCount; i++) {
            struct dyld_image_info info = infos->infoArray[i];
            NSString* p = info.imageFilePath ? @(info.imageFilePath) : @"?";

            if(!probe_is_foreign_image(p, appPath)) {
                [out appendFormat:@"  %@\n", p];
            }
        }
    } else {
        [out appendString:@"  (dyld_all_image_infos unavailable)\n"];
    }
}

static void probe_section_2(NSMutableString* out, NSString* appPath) {
    [out appendString:@"\n== 2. dyld API view ==\n"];
    uint32_t count = _dyld_image_count();
    [out appendFormat:@"_dyld_image_count = %u\n", count];

    for(uint32_t i = 0; i < count; i++) {
        const char* n = _dyld_get_image_name(i);
        NSString* p = n ? @(n) : @"?";

        if(!probe_is_foreign_image(p, appPath)) {
            [out appendFormat:@"  %@\n", p];
        }
    }
}

static void probe_section_3(NSMutableString* out, NSFileManager* fm) {
    [out appendString:@"\n== 3. jailbreak path probes (fileExistsAtPath) ==\n"];
    NSArray* jbPaths = @[
        @"/var/jb",
        @"/var/jb/usr/lib/libhooker.dylib",
        @"/var/jb/usr/lib/libsubstitute.0.dylib",
        @"/var/jb/usr/lib/libellekit.dylib",
        @"/var/jb/Library/MobileSubstrate/DynamicLibraries",
        @"/var/jb/bin/sbreload",
        @"/usr/lib/libhooker.dylib",
        @"/usr/lib/libsubstitute.0.dylib",
        @"/usr/lib/libsubstrate.dylib",
        @"/usr/lib/libellekit.dylib",
        @"/usr/lib/pspawn_payload-stg2.dylib",
        @"/usr/lib/tweakloader.dylib",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/usr/bin/sbreload",
        @"/bin/bash",
        @"/Applications/Cydia.app",
        @"/cores",
        @"/usr/libexec/cydia"
    ];

    for(NSString* p in jbPaths) {
        [out appendFormat:@"  %@ %@\n", p, [fm fileExistsAtPath:p] ? @"EXISTS" : @"no"];
    }

    NSArray* preboot = [fm contentsOfDirectoryAtPath:@"/private/preboot" error:nil];
    NSMutableArray* jbdirs = [NSMutableArray new];

    for(NSString* d in preboot) {
        if([d hasPrefix:@"jb-"] || [d hasPrefix:@"procursus"]) {
            [jbdirs addObject:d];
        }
    }

    [out appendFormat:@"  /private/preboot jailbreak dirs: %@\n", jbdirs];
}

static void probe_section_4(NSMutableString* out) {
    [out appendString:@"\n== 4. URL scheme probes ==\n"];

    for(NSString* s in @[@"cydia://", @"sileo://", @"zbra://", @"xina://", @"filza://"]) {
        BOOL openable = [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:s]];
        [out appendFormat:@"  %-12@ %@\n", s, openable ? @"OPENABLE" : @"no"];
    }
}

static NSMutableArray* probe_section_5(NSMutableString* out, NSArray* hiddenMarkers) {
    [out appendString:@"\n== 5. dladdr/dlsym on hidden images ==\n"];
    // Two independent probes:
    //  A. dladdr on addresses taken from the DIRECT memory read — the
    //     imageLoadAddress (mach_header) of every jailbreak-path entry, plus
    //     an offset into __TEXT — tested BEFORE the dlsym checks below, so a
    //     hidden dlsym result (NULL) can never suppress the dladdr probe.
    //  B. dlsym per candidate symbol, independently; a NULL result only
    //     reports that symbol.
    struct dyld_all_image_infos* infos5 = probe_direct_infos();
    NSMutableArray* hiddenAddrs = [NSMutableArray new];

    if(infos5 && infos5->infoArray) {
        for(uint32_t i = 0; i < infos5->infoArrayCount; i++) {
            struct dyld_image_info info = infos5->infoArray[i];
            NSString* p = info.imageFilePath ? @(info.imageFilePath) : @"";

            for(NSString* marker in hiddenMarkers) {
                if([p containsString:marker]) {
                    if(info.imageLoadAddress) {
                        [hiddenAddrs addObject:[NSValue valueWithPointer:(void *)((uintptr_t)info.imageLoadAddress + 0x1000)]];
                    }
                    break;
                }
            }
        }
    }

    if(![hiddenAddrs count]) {
        [out appendString:@"  no jailbreak-path images visible in the direct read (memory hiding active, or none loaded) — dladdr probe skipped\n"];
    } else {
        [out appendString:@"  dladdr on hidden-image addresses (direct-read mach_header + __TEXT offset):\n"];

        for(NSValue* v in hiddenAddrs) {
            void* addr = [v pointerValue];
            Dl_info info;
            BOOL got = dladdr(addr, &info);
            [out appendFormat:@"    %p -> %@\n", addr, (got && info.dli_fname) ? @(info.dli_fname) : @"(no info)"];
        }
    }

    for(NSString* symName in @[@"hookObjcMessage", @"MSHookFunction", @"MSHookMessageEx"]) {
        void* sym = dlsym(RTLD_DEFAULT, [symName UTF8String]);

        if(!sym) {
            [out appendFormat:@"  %-20@ not resolvable (hidden or absent)\n", symName];
            continue;
        }

        Dl_info info;
        BOOL gotInfo = dladdr(sym, &info) && info.dli_fname;
        [out appendFormat:@"  %-20@ %p  dladdr: %@\n", symName, sym, gotInfo ? @(info.dli_fname) : @"?"];
    }

    return hiddenAddrs;
}

static void probe_section_6(NSMutableString* out, NSFileManager* fm, NSArray* hiddenMarkers) {
    [out appendString:@"\n== 6. add/remove image stress (unloadable test dylib) ==\n"];
    // The stress library must be a real ON-DISK dylib that dlclose can fully
    // unload: shared-cache images (e.g. /usr/lib/libxml2.dylib) may not be
    // unloadable and behave differently in the infoArray. shdwtestlib ships
    // with the app (second theos target) and is copied to a container path
    // before dlopen, so the path is never in Shadow's restricted domain on
    // either rootful or rootless.
    // theos emits libshdwtestlib.dylib for the LIBRARY_NAME=shdwtestlib
    // library target; the unprefixed spelling is accepted too, so a
    // mismatched install still works. lib-prefixed is preferred (matches
    // what theos actually installs).
    NSArray* testLibNames = @[@"libshdwtestlib.dylib", @"shdwtestlib.dylib"];
    NSString* installedLib = nil;
    NSString* foundLibName = nil;

    // Bundle copy source first (app bundle, then runtime lib dirs — on
    // rootless the install lands under /var/jb/usr/lib), both spellings.
    for(NSString* dir in @[
        [[NSBundle mainBundle] bundlePath],
        @"/usr/lib",
        @"/var/jb/usr/lib"
    ]) {
        for(NSString* name in testLibNames) {
            NSString* cand = [dir stringByAppendingPathComponent:name];

            if([fm fileExistsAtPath:cand]) {
                installedLib = cand;
                foundLibName = name;
                break;
            }
        }

        if(installedLib) {
            break;
        }
    }

    NSString* stressPath = nil;

    if(installedLib) {
        [out appendFormat:@"  stress dylib source: %@ (spelling: %@)\n", installedLib, foundLibName];
        NSString* docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        stressPath = [docs stringByAppendingPathComponent:foundLibName];
        [fm removeItemAtPath:stressPath error:nil];

        NSError* copyErr = nil;

        if(![fm copyItemAtPath:installedLib toPath:stressPath error:&copyErr]) {
            // Rootless: the bundle copy source can sit under /var/jb and be
            // hidden before the copy runs. Log clearly and fall through to
            // the runtime scan below — never abort the stress section.
            [out appendFormat:@"  copy %@ -> %@ FAILED (%@); falling back to runtime scan\n", installedLib, stressPath, copyErr];
            stressPath = nil;
        } else {
            [out appendFormat:@"  stress dylib staged at %@\n", stressPath];
        }
    }

    if(!stressPath) {
        // Fallback: find a non-shared-cache dylib already on disk. A shared-
        // cache image is already in the image list at spawn, so "not in the
        // pre-load infoArray and dlopen succeeds" selects a genuinely
        // loadable/unloadable on-disk image. Hidden-domain paths (restricted
        // by Shadow) are excluded — tracking can't be verified for them.
        [out appendString:@"  shipped test dylib not found; probing for an on-disk dylib...\n"];
        struct dyld_all_image_infos* pre = probe_direct_infos();
        NSMutableSet* preloaded = [NSMutableSet set];

        if(pre && pre->infoArray) {
            for(uint32_t i = 0; i < pre->infoArrayCount; i++) {
                if(pre->infoArray[i].imageFilePath) {
                    [preloaded addObject:@(pre->infoArray[i].imageFilePath)];
                }
            }
        }

        for(NSString* dir in @[@"/usr/lib", @"/var/jb/usr/lib"]) {
            for(NSString* e in [fm contentsOfDirectoryAtPath:dir error:nil]) {
                if(![e hasSuffix:@".dylib"]) {
                    continue;
                }

                NSString* full = [dir stringByAppendingPathComponent:e];
                BOOL hiddenDomain = [full hasPrefix:@"/var/jb"] || [full hasPrefix:@"/Library/"];
                BOOL jbName = NO;

                for(NSString* marker in hiddenMarkers) {
                    if([full containsString:marker]) {
                        jbName = YES;
                        break;
                    }
                }

                if(hiddenDomain || jbName || [preloaded containsObject:full]) {
                    continue;
                }

                void* h = dlopen([full fileSystemRepresentation], RTLD_NOW);

                if(h) {
                    stressPath = full;
                    dlclose(h);
                    [out appendFormat:@"  fallback stress dylib: %@\n", full];
                    break;
                }
            }

            if(stressPath) {
                break;
            }
        }
    }

    if(!stressPath) {
        [out appendString:@"  SKIPPED: no unloadable on-disk dylib found (install shdwtestlib with the app)\n"];
    } else {
        struct dyld_all_image_infos* base = probe_direct_infos();
        uint32_t baseCount = (base && base->infoArray) ? base->infoArrayCount : 0;
        [out appendFormat:@"  baseline infoArrayCount = %u (expected range [%u, %u] while stressing)\n", baseCount, baseCount, baseCount + 1];

        // Concurrent direct-memory reader: continuously walks the infoArray
        // while the stress runs, counting torn reads (a mid-walk NULL/NULL
        // entry) and reporting the max entries walked vs the expected range.
        __block _Atomic(BOOL) readerStop = NO;
        __block uint32_t readerRuns = 0;
        __block uint32_t readerTorn = 0;
        __block uint32_t readerMax = 0;
        dispatch_queue_t readerQueue = dispatch_queue_create("dyldprobe.reader", DISPATCH_QUEUE_SERIAL);

        dispatch_async(readerQueue, ^{
            while(!atomic_load_explicit(&readerStop, memory_order_relaxed)) {
                struct dyld_all_image_infos* infos = probe_direct_infos();

                if(!infos || !infos->infoArray || infos->infoArrayCount == 0) {
                    usleep(1000);
                    continue;
                }

                uint32_t count = infos->infoArrayCount;
                uint32_t walked = 0;
                BOOL torn = NO;
                uint32_t cap = MIN(count, 8192u);

                for(uint32_t i = 0; i < cap; i++) {
                    struct dyld_image_info info = infos->infoArray[i];

                    if(!info.imageLoadAddress && !info.imageFilePath) {
                        torn = YES;
                        break;
                    }

                    walked++;
                }

                if(torn) {
                    readerTorn++;
                }

                if(walked > readerMax) {
                    readerMax = walked;
                }

                readerRuns++;
                usleep(1000);
            }
        });

        BOOL stressOK = YES;
        // The probe marker only exists in the shipped shdwtestlib; the
        // fallback dylib can't export it, so only require it there.
        BOOL expectMarker = [stressPath hasSuffix:testLibNames[0]] || [stressPath hasSuffix:testLibNames[1]];

        for(int i = 0; i < 8; i++) {
            void* handle = dlopen([stressPath fileSystemRepresentation], RTLD_NOW);

            if(!handle) {
                // Capture dlerror() once: a second call clears the first
                // result, so ?: on two calls can log NULL for a real error.
                const char* dlErr = dlerror();
                [out appendFormat:@"  iter %d: dlopen(%@) failed: %s\n", i, stressPath, dlErr ? dlErr : "?"];
                stressOK = NO;
                break;
            }

            // Confirm the handle really is OUR dylib, not a cached image.
            void* marker = dlsym(handle, "shdwtestlib_probe_marker");
            struct dyld_all_image_infos* live = probe_direct_infos();
            BOOL seenLoaded = NO;

            if(live && live->infoArray) {
                for(uint32_t j = 0; j < live->infoArrayCount; j++) {
                    NSString* p = live->infoArray[j].imageFilePath ? @(live->infoArray[j].imageFilePath) : @"";

                    if([p isEqualToString:stressPath]) {
                        seenLoaded = YES;
                    }

                    for(NSString* marker2 in hiddenMarkers) {
                        if([p containsString:marker2]) {
                            [out appendFormat:@"  iter %d: HIDDEN IMAGE LEAKED: %@\n", i, p];
                            stressOK = NO;
                        }
                    }
                }
            }

            // (a) loaded state: the direct read must show the image while
            // loaded (its container path is never in the hidden domain —
            // absent would mean tracking is broken).
            if(!seenLoaded || (expectMarker && !marker)) {
                [out appendFormat:@"  iter %d: FAILED — %@ not visible in direct infoArray while loaded (marker %@)\n", i, stressPath, marker ? @"OK" : @"MISSING"];
                stressOK = NO;
            }

            dlclose(handle);

            struct dyld_all_image_infos* after = probe_direct_infos();
            BOOL stillLoaded = NO;

            if(after && after->infoArray) {
                for(uint32_t j = 0; j < after->infoArrayCount; j++) {
                    NSString* p = after->infoArray[j].imageFilePath ? @(after->infoArray[j].imageFilePath) : @"";

                    if([p isEqualToString:stressPath]) {
                        stillLoaded = YES;
                    }
                }
            }

            // (b) after dlclose: the image must be gone — a shared-cache
            // image (the old libxml2 case) can survive dlclose and stay
            // visible in the read.
            if(stillLoaded) {
                [out appendFormat:@"  iter %d: FAILED — %@ still visible in direct infoArray after dlclose (not unloadable or stale read)\n", i, stressPath];
                stressOK = NO;
            }
        }

        atomic_store_explicit(&readerStop, YES, memory_order_relaxed);
        dispatch_sync(readerQueue, ^{});
        [out appendFormat:@"  concurrent reader: %u runs, max entries walked = %u (expected <= %u), torn reads = %u\n", readerRuns, readerMax, baseCount + 1, readerTorn];

        if(readerTorn > 0) {
            [out appendString:@"  concurrent reader: TORN reads observed — mirror/read published inconsistently\n"];
            stressOK = NO;
        }

        if(readerMax > baseCount + 1) {
            [out appendString:@"  concurrent reader: max exceeded expected range — over-read (count/array mismatch)\n"];
            stressOK = NO;
        }

        [out appendFormat:@"  stress result: %@\n", stressOK ? @"OK" : @"FAILED"];
    }
}

static void probe_section_7(NSMutableString* out) {
    [out appendString:@"\n== 7. uuid / infoArrayChangeTimestamp invariants ==\n"];

    struct dyld_all_image_infos* invariants = probe_direct_infos();

    if(invariants) {
        [out appendFormat:@"  version = %u\n", invariants->version];
        [out appendFormat:@"  infoArrayChangeTimestamp = %llu\n", (unsigned long long)invariants->infoArrayChangeTimestamp];
        [out appendFormat:@"  infoArrayCount = %lu, uuidArrayCount = %lu\n", (unsigned long)invariants->infoArrayCount, (unsigned long)invariants->uuidArrayCount];

        if(invariants->uuidArray) {
            for(uint32_t i = 0; i < invariants->uuidArrayCount && i < 4; i++) {
                const unsigned char* u = invariants->uuidArray[i].imageUUID;
                [out appendFormat:@"  uuid[%u] %p: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
                    i, invariants->uuidArray[i].imageLoadAddress,
                    u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
                    u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]];
            }
        }
    } else {
        [out appendString:@"  (dyld_all_image_infos unavailable)\n"];
    }
}

static void probe_section_8(NSMutableString* out, NSArray* hiddenMarkers, NSMutableArray* hiddenAddrs) {
    [out appendString:@"\n== 8. denyFishHook(dladdr) revert resistance ==\n"];
    // IOSSecuritySuite's FishHookChecker builds a fishhook `rebinding` for
    // "dladdr" pointing at a dummy function and calls rebind_symbols() to
    // revert the symbol. Shadow hooks dladdr/dlsym with INLINE (ElleKit)
    // trampolines, which fishhook-style pointer rebinding cannot undo.
    // Replicate that exact revert, then verify dladdr still resolves
    // coherently. Deliberately LAST so a revert-induced failure can never
    // suppress sections 1-7, and fail-soft throughout: an unavailable
    // rebind_symbols skips the section, and nothing here can abort.
    @try {
        void (*rebindSymbols)(struct rebinding*, int) = (void (*)(struct rebinding*, int))dlsym(RTLD_DEFAULT, "rebind_symbols");

        if(!rebindSymbols) {
            [out appendString:@"  rebind_symbols unavailable — section skipped (no fishhook-linked image in process)\n"];
        } else {
            void* replaced = NULL;
            struct rebinding r = {"dladdr", (void*)dyldprobe_dummy_dladdr, &replaced};
            rebindSymbols(&r, 1);
            [out appendFormat:@"  rebind_symbols({\"dladdr\" -> dummy}) called; replaced = %p %@\n", replaced, replaced ? @"(a binding was patched — the revert really ran)" : @"(no binding patched)"];

            // Targets: ProbeReport itself (a benign app-binary address —
            // Shadow answers it with the app path), plus any jailbreak-path
            // addresses section 5's direct read found — the strongest
            // adjudication: a hidden image leaking out of dladdr after the
            // rebind means the inline hook was reverted.
            NSMutableArray* targets = [NSMutableArray arrayWithObject:[NSValue valueWithPointer:(void*)ProbeReport]];
            [targets addObjectsFromArray:hiddenAddrs];
            BOOL sectionOK = YES;

            for(NSValue* v in targets) {
                void* addr = [v pointerValue];
                Dl_info info;
                BOOL got = dladdr(addr, &info);

                if(!got) {
                    [out appendFormat:@"    %p -> no info (dummy took over — rebind succeeded; expected when no inline hook is active)\n", addr];
                    sectionOK = NO;
                    continue;
                }

                NSString* name = info.dli_fname ? @(info.dli_fname) : @"(null)";
                BOOL jbPath = NO;

                for(NSString* marker in hiddenMarkers) {
                    if([name containsString:marker]) {
                        jbPath = YES;
                        break;
                    }
                }

                if(jbPath) {
                    [out appendFormat:@"    %p -> %@ — JAILBREAK PATH LEAKED through dladdr (revert succeeded)\n", addr, name];
                    sectionOK = NO;
                } else {
                    [out appendFormat:@"    %p -> %@ — resolves; mask/benign answer intact\n", addr, name];
                }
            }

            [out appendFormat:@"  result: %@\n", sectionOK ? @"PASS — dladdr survived the rebind attempt (no crash, coherent Dl_info, hide holds)" : @"FAIL — the rebind disturbed dladdr (inline hook reverted, or no Shadow active)"];
        }
    } @catch(NSException* e) {
        [out appendFormat:@"  EXCEPTION in rebind probe: %@ — FAIL (rebind disturbed dladdr)\n", e];
    }
}

// Section 9: denyFishHook-style GOT revert on a FISHHOOK-rebound C function.
// v5-PLAN AR5 documents the residual: denyFishHook reverts GOT slots only —
// the inline-pinned dladdr/dlsym/dlopen_internal are immune (section 8), but
// the ~60 fishhook-rebound libc/mach/sandbox/mem hooks are revertible. This
// section proves the residual is real and exploitable: rebind the GOT slot
// for access() (a fishhook-rebound libc export) and show the jailbreak-path
// filter is defeated. Deliberately LAST (after section 8) and fail-soft.
static int dyldprobe_dummy_access(const char* path, int mode) {
    return 0;  // "path exists" — the unfiltered answer a reverted access() gives on a JB device
}

static void probe_section_9(NSMutableString* out) {
    [out appendString:@"\n== 9. denyFishHook GOT revert on a fishhook-rebound C function (documented residual) ==\n"];
    @try {
        void (*rebindSymbols)(struct rebinding*, int) = (void (*)(struct rebinding*, int))dlsym(RTLD_DEFAULT, "rebind_symbols");

        if(!rebindSymbols) {
            [out appendString:@"  rebind_symbols unavailable — section skipped\n"];
            return;
        }

        // Baseline: with Shadow active, access() on a jailbreak path is filtered.
        int before = access("/var/jb", F_OK);
        [out appendFormat:@"  access(\"/var/jb\", F_OK) before revert = %d %@\n", before, before == 0 ? @"(path VISIBLE — no filter active)" : @"(filtered — Shadow hook active)"];

        // Replicate denyFishHook: rebind the GOT slot for "access" to a
        // replacement. If the slot was fishhook-rebound by Shadow, rebind
        // finds and patches it (replaced != NULL) — the revert ran.
        void* replaced = NULL;
        struct rebinding r = {"access", (void*)dyldprobe_dummy_access, &replaced};
        rebindSymbols(&r, 1);
        [out appendFormat:@"  rebind_symbols({\"access\" -> dummy}) called; replaced = %p %@\n", replaced, replaced ? @"(GOT slot WAS rebound — fishhook hook revertible)" : @"(no GOT slot patched — hook not fishhook-rebound)"];

        // After: does the JB path now resolve? If yes, the filter is defeated.
        int after = access("/var/jb", F_OK);
        [out appendFormat:@"  access(\"/var/jb\", F_OK) after revert = %d %@\n", after, after == 0 ? @"(path VISIBLE — filter DEFEATED, residual exploited)" : @"(still filtered)"];

        BOOL residual = (replaced != NULL) && (after == 0);
        [out appendFormat:@"  result: %@\n", residual ? @"RESIDUAL CONFIRMED — fishhook-rebound C hooks are revertible by denyFishHook (documented unfixable)" : @"hook survived the revert (inline-pinned, or no Shadow active)"];
    } @catch(NSException* e) {
        [out appendFormat:@"  EXCEPTION in revert probe: %@\n", e];
    }
}

static NSString* ProbeReport(void) {
    NSMutableString* out = [NSMutableString string];
    NSString* appPath = [[NSBundle mainBundle] bundlePath];
    NSFileManager* fm = [NSFileManager defaultManager];

    probe_section_1(out, appPath);
    probe_section_2(out, appPath);
    probe_section_3(out, fm);
    probe_section_4(out);

    // Markers used to recognize jailbreak-path images in the direct reads
    // (shared by sections 5 and 6).
    NSArray* hiddenMarkers = probe_hidden_markers();

    NSMutableArray* hiddenAddrs = probe_section_5(out, hiddenMarkers);
    probe_section_6(out, fm, hiddenMarkers);
    probe_section_7(out);
    probe_section_8(out, hiddenMarkers, hiddenAddrs);
    probe_section_9(out);

    [out appendString:@"\n== done ==\n"];
    return out;
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow* window;
@end

@implementation AppDelegate {
    UITextView* _textView;
}

- (void)_refresh {
    probe_write_machine_report(NULL);
    _textView.text = ProbeReport();
    fprintf(stderr, "%s\n", [_textView.text UTF8String]);
}

- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)launchOptions {
    // Write the report FIRST — before any window setup — so it lands even if
    // UI initialization stalls (headless/SSH-launched contexts).
    NSString* report;
    @autoreleasepool {
        // Capture the clean launch state before the human-only stress report
        // deliberately rebinds GOT slots in sections 8 and 9.
        probe_write_machine_report(NULL);
        report = ProbeReport();
        fprintf(stderr, "%s\n", [report UTF8String]);
    }
    CGRect frame = [[UIScreen mainScreen] bounds];
    self.window = [[UIWindow alloc] initWithFrame:frame];

    UIViewController* vc = [UIViewController new];
    vc.view = [[UIView alloc] initWithFrame:frame];

    UIButton* refresh = [UIButton buttonWithType:UIButtonTypeSystem];
    refresh.frame = CGRectMake(0, 20, frame.size.width, 44);
    [refresh setTitle:@"Refresh" forState:UIControlStateNormal];
    [refresh addTarget:self action:@selector(_refresh) forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:refresh];

    _textView = [[UITextView alloc] initWithFrame:CGRectMake(0, 64, frame.size.width, frame.size.height - 64)];
    _textView.editable = NO;
    _textView.font = [UIFont systemFontOfSize:11];
    // Reuse the launch report; _refresh (Refresh button) builds another on demand.
    _textView.text = report;
    [vc.view addSubview:_textView];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    return YES;
}

@end

int main(int argc, char* argv[]) {
    @autoreleasepool {
        BOOL headless = NO;
        for(int i = 1; i < argc; i++) {
            if(strcmp(argv[i], "--shadow-headless-producer") == 0) {
                headless = YES;
                break;
            }
        }
        NSString* failure = nil;
        BOOL written = probe_write_machine_report(&failure);
        if(headless) {
            if(!written) {
                fprintf(stderr, "dyldprobe headless report failure: %s\n", failure.UTF8String ?: "unknown");
                return 2;
            }
            for(;;) pause();
        }
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
