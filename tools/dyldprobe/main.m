#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <mach/task_info.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <errno.h>
#import <limits.h>
#import <stdatomic.h>
#import <stdio.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

static uint64_t gProbeStartTicks = 0;
static mach_timebase_info_data_t gProbeTimebase = {0, 0};
static NSString* const kProbePackagedStressPath = @"@executable_path/shdwtestlib.dylib";

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
//
// The machine JSON report is the formal evidence: it contains the direct and
// public dyld views plus callback/stress results. The UI keeps only supplemental
// manual diagnostics that are not part of that contract. Run it with Shadow
// disabled for this app (baseline), then with Shadow enabled and all hooks on.

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

static NSString* probe_string_at_pointer(const char* pointer) {
    if(!pointer) return @"";
    char bytes[PATH_MAX];
    size_t length = 0;
    while(length < sizeof(bytes) - 1) {
        vm_address_t address = (vm_address_t)(uintptr_t)pointer + length;
        vm_size_t pageRemaining = vm_page_size - (address % vm_page_size);
        vm_size_t requested = MIN((vm_size_t)(sizeof(bytes) - 1 - length), pageRemaining);
        vm_size_t copied = 0;
        kern_return_t result = vm_read_overwrite(mach_task_self(), address, requested,
            (vm_address_t)(uintptr_t)(bytes + length), &copied);
        if(result != KERN_SUCCESS || copied == 0) return nil;
        char* terminator = memchr(bytes + length, '\0', copied);
        if(terminator) {
            *terminator = '\0';
            return [NSString stringWithUTF8String:bytes];
        }
        length += copied;
    }
    return nil;
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
        NSString* path = probe_string_at_pointer(images[i].imageFilePath) ?: @"<invalid>";
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
        NSString* path = probe_string_at_pointer(_dyld_get_image_name(i)) ?: @"<invalid>";
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
    if(!source) return kProbePackagedStressPath;

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
        NSString* candidate = probe_string_at_pointer(probe.infos->infoArray[i].imageFilePath);
        if(candidate && probe_paths_match(path, candidate.fileSystemRepresentation)) return YES;
    }
    return NO;
}

static BOOL probe_direct_uuid_contains_path(ProbeTaskDyldInfo probe, NSString* path) {
    if(!probe.valid || !probe.infos->infoArray || !probe.infos->uuidArray) return NO;
    for(uint32_t i = 0; i < probe.infos->infoArrayCount; i++) {
        const struct dyld_image_info* image = &probe.infos->infoArray[i];
        NSString* candidate = probe_string_at_pointer(image->imageFilePath);
        if(!candidate || !probe_paths_match(path, candidate.fileSystemRepresentation)) continue;
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
    NSString* observedStressPath = stressPath;

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
                const char* error = dlerror();
                stagingFailure = error ? [NSString stringWithUTF8String:error] : @"dlopen failed";
                loaded = NO;
                unloaded = NO;
                markerOK = NO;
                break;
            }
            void* marker = dlsym(handle, "shdwtestlib_probe_marker");
            if(!marker) markerOK = NO;
            Dl_info markerInfo = {0};
            if(marker && dladdr(marker, &markerInfo) && markerInfo.dli_fname) {
                observedStressPath = [NSString stringWithUTF8String:markerInfo.dli_fname];
            }
            BOOL visible = NO, uuid = NO;
            for(uint32_t retry = 0; retry < 20; retry++) {
                ProbeTaskDyldInfo current = probe_task_dyld_info();
                visible = visible || probe_direct_contains_path(current, observedStressPath);
                uuid = uuid || probe_direct_uuid_contains_path(current, observedStressPath);
                if(visible && uuid) break;
                usleep(1000);
            }
            if(!visible) loaded = NO;
            if(!uuid) uuidVisible = NO;
            BOOL gone = dlclose(handle) == 0;
            for(uint32_t retry = 0; gone && retry < 20; retry++) {
                if(!probe_direct_contains_path(probe_task_dyld_info(), observedStressPath)) break;
                if(retry == 19) gone = NO;
                else usleep(1000);
            }
            if(!gone) unloaded = NO;
        }
        atomic_store_explicit(&readerStop, YES, memory_order_relaxed);
        dispatch_sync(readerQueue, ^{});
    }

    if(stressPath && ![stressPath isEqualToString:kProbePackagedStressPath]) {
        [fm removeItemAtPath:stressPath error:nil];
    }
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
            @"path" : observedStressPath ?: @"",
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
        NSString* path = probe_string_at_pointer(_dyld_get_image_name(i)) ?: @"<invalid>";
        publicSlides[address] = slide;
        [publicRows addObject:@{
            @"path" : path, @"address" : address, @"header" : address,
            @"slide" : slide, @"uuid" : uuids[address] ?: [NSNull null],
        }];
    }

    NSMutableArray<NSDictionary*>* memoryRows = [NSMutableArray new];
    if(probe.valid && probe.infos->infoArray) {
        for(uint32_t i = 0; i < probe.infos->infoArrayCount; i++) {
            struct dyld_image_info entry = probe.infos->infoArray[i];
            NSString* address = probe_pointer_string(entry.imageLoadAddress);
            [memoryRows addObject:@{
                @"path" : probe_string_at_pointer(entry.imageFilePath) ?: @"<invalid>",
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

static NSDictionary* probe_machine_report(NSDictionary* context, NSString** failure) {
    if(failure) *failure = nil;
    if(![context isKindOfClass:[NSDictionary class]]) {
        if(failure) *failure = @"launch context unavailable";
        return nil;
    }

    for(NSString* key in @[@"run_id", @"row_id", @"requested_mode", @"nonce", @"probe_revision"]) {
        if(![context[key] isKindOfClass:[NSString class]] || ![context[key] length]) {
            if(failure) *failure = [NSString stringWithFormat:@"launch context key invalid: %@", key];
            return nil;
        }
    }
    NSString* mode = context[@"requested_mode"];
    if(![mode isEqualToString:@"uninjected"] && ![mode isEqualToString:@"injected"]) {
        if(failure) *failure = @"launch context mode invalid";
        return nil;
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
    return report;
}

static BOOL probe_write_json_report(NSDictionary* report, NSString* path, NSString** failure) {
    NSError* error = nil;
    NSData* data = report ? [NSJSONSerialization dataWithJSONObject:report options:0 error:&error] : nil;
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

static BOOL probe_write_machine_report(NSString** failure) {
    NSString* documents = probe_documents_directory();
    NSDictionary* context = probe_launch_context(documents);
    NSDictionary* report = probe_machine_report(context, failure);
    if(!documents || !report) return NO;
    NSString* path = [documents stringByAppendingPathComponent:
        [NSString stringWithFormat:@"dyldprobe-%@.json", context[@"nonce"]]];
    return probe_write_json_report(report, path, failure);
}

static NSDictionary* probe_dashboard_check(NSString* identifier, NSString* name,
                                            BOOL passed, NSString* message) {
    return @{@"id" : identifier, @"name" : name, @"passed" : @(passed),
             @"message" : message ?: (passed ? @"Passed" : @"Failed")};
}

static BOOL probe_write_dashboard_report(NSString** failure) {
    errno = 0;
    int canaryResult = stat("/var/jb", &(struct stat){0});
    int canaryErrno = errno;
    BOOL injected = canaryResult == -1 && canaryErrno == ENOENT;
    NSDictionary* context = @{
        @"run_id" : @"shadow-harness", @"row_id" : @"dyldprobe",
        @"requested_mode" : injected ? @"injected" : @"uninjected",
        @"nonce" : @"dashboard", @"probe_revision" : @"dashboard-v1",
    };
    NSDictionary* formal = probe_machine_report(context, failure);
    if(!formal) return NO;

    NSDictionary* observations = formal[@"observations"];
    NSDictionary* dyld = observations[@"dyld"];
    NSString* aggregate = observations[@"aggregate"] ?: @"SETUP-FAIL";
    NSMutableArray<NSDictionary*>* checks = [NSMutableArray new];
    [checks addObject:probe_dashboard_check(@"dyld.aggregate", @"Aggregate",
        [aggregate isEqualToString:@"PASS"], aggregate)];

    NSDictionary* canary = [formal[@"canary"] isKindOfClass:[NSDictionary class]] ? formal[@"canary"] : nil;
    [checks addObject:probe_dashboard_check(@"dyld.canary", @"Jailbreak path canary",
        [canary[@"status"] isEqualToString:@"PASS"], canary[@"status"] ?: @"Control exposed /var/jb")];
    for(NSArray* item in @[
        @[@"dyld.fidelity", @"Dyld fidelity", dyld[@"status"] ?: @"FAIL"],
        @[@"dyld.address_uuid", @"Address and UUID consistency", dyld[@"address_uuid"] ?: @"FAIL"],
        @[@"dyld.concurrency", @"Concurrent reads", dyld[@"concurrency"][@"status"] ?: @"FAIL"],
        @[@"dyld.stress", @"Load/unload stress", dyld[@"stress"][@"status"] ?: @"FAIL"],
    ]) {
        NSString* status = item[2];
        [checks addObject:probe_dashboard_check(item[0], item[1], [status isEqualToString:@"PASS"], status)];
    }

    NSArray* directHidden = observations[@"direct_memory_view"][@"hidden_images"] ?: @[];
    NSArray* publicHidden = observations[@"public_api_view"][@"hidden_images"] ?: @[];
    [checks addObject:probe_dashboard_check(@"dyld.direct_hidden", @"Direct memory image hiding",
        directHidden.count == 0, [NSString stringWithFormat:@"%lu hidden image leak(s)", (unsigned long)directHidden.count])];
    [checks addObject:probe_dashboard_check(@"dyld.public_hidden", @"Public API image hiding",
        publicHidden.count == 0, [NSString stringWithFormat:@"%lu hidden image leak(s)", (unsigned long)publicHidden.count])];

    for(NSDictionary* callback in dyld[@"callbacks"] ?: @[]) {
        NSString* status = callback[@"status"] ?: @"FAIL";
        NSString* name = [NSString stringWithFormat:@"Callback %@", callback[@"id"] ?: @"?"];
        [checks addObject:probe_dashboard_check([NSString stringWithFormat:@"dyld.callback.%@", callback[@"id"] ?: @"?"],
            name, [status isEqualToString:@"PASS"], status)];
    }

    NSString* outcome = [aggregate isEqualToString:@"PASS"] ? @"clean" :
        ([aggregate isEqualToString:@"SETUP-FAIL"] ? @"error" : @"jailbroken");
    NSDictionary* dashboard = @{
        @"schemaVersion" : @1,
        @"sdk" : @{@"id" : @"dyldprobe", @"name" : @"dyldprobe", @"version" : @"1.0.0"},
        @"outcome" : outcome,
        @"generatedAt" : [NSISO8601DateFormatter.new stringFromDate:[NSDate date]],
        @"rounds" : @[@{@"phase" : @"dyld fidelity", @"clean" : @([outcome isEqualToString:@"clean"]), @"checks" : checks}],
        @"formal" : formal,
    };
    NSString* directory = @"/var/mobile/Documents/ShadowDetectorTests";
    if(![NSFileManager.defaultManager createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:nil]) {
        if(failure) *failure = @"cannot create dashboard results directory";
        return NO;
    }
    return probe_write_json_report(dashboard,
        [directory stringByAppendingPathComponent:@"dyldprobe.json"], failure);
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
            NSString* p = probe_string_at_pointer(info.imageFilePath) ?: @"<invalid>";

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
    // suppress earlier supplemental diagnostics, and fail-soft throughout: an unavailable
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
    NSFileManager* fm = [NSFileManager defaultManager];

    [out appendString:@"Formal JSON evidence is written once at launch; supplemental manual diagnostics follow.\n"];
    probe_section_3(out, fm);
    probe_section_4(out);

    // Markers used to recognize jailbreak-path images in the direct reads.
    NSArray* hiddenMarkers = probe_hidden_markers();

    NSMutableArray* hiddenAddrs = probe_section_5(out, hiddenMarkers);
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

- (void)_runForShadowHarness {
    NSString* failure = nil;
    if(!probe_write_dashboard_report(&failure)) {
        _textView.text = [NSString stringWithFormat:@"Dashboard report failed: %@", failure ?: @"unknown error"];
        return;
    }
    _textView.text = @"dyld fidelity report complete";
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"shadow-detectors://refresh"]
        options:@{} completionHandler:nil];
}

- (void)_refresh {
    _textView.text = ProbeReport();
    fprintf(stderr, "%s\n", [_textView.text UTF8String]);
}

- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)launchOptions {
    NSURL* launchURL = launchOptions[UIApplicationLaunchOptionsURLKey];
    BOOL launchedFromHarness = [launchURL.scheme isEqualToString:@"shadow-dyldprobe"];
    NSString* report = launchedFromHarness ? @"Running dyld fidelity probe…" :
        @"Tap Refresh to run supplemental diagnostics.";
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
    if(launchedFromHarness) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self _runForShadowHarness]; });
    }
    return YES;
}

- (BOOL)application:(UIApplication*)application openURL:(NSURL*)url options:(NSDictionary*)options {
    if(![url.scheme isEqualToString:@"shadow-dyldprobe"]) return NO;
    [self _runForShadowHarness];
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
