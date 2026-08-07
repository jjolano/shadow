#import <Shadow/SystemRulesGenerator.h>
#import <Shadow/Core+Utilities.h>
#import <RootBridge.h>

#import <fcntl.h>
#import <string.h>
#import <sys/attr.h>
#import <sys/mount.h>
#import <sys/snapshot.h>
#import <unistd.h>

#import "../common.h"

#ifndef _SYS_SNAPSHOT_H_
extern int fs_snapshot_list(int fd, struct attrlist* alist, void* buf, size_t bufsize, uint32_t flags);
extern int fs_snapshot_mount(int fd, const char* dir, const char* name, uint32_t flags);
#endif

@implementation SystemRulesGenerator

typedef struct {
    const char* path;
    int depth; // -1 = unlimited, 1 = direct children only
} SystemZone;

// /usr covers /usr/lib, /usr/bin, /usr/sbin, /usr/libexec and /usr/share at full depth.
static const SystemZone kSystemZones[] = {
    {"/usr", -1},
    {"/bin", -1},
    {"/sbin", -1},
    {"/Applications", -1},
    {"/Library", 1},
    {"/System", 1},
    {"/System/Library", 1},
    {"/System/Cryptexes", 1},
    {"/System/Cryptexes/App", 1},
    {"/System/Cryptexes/OS", 1},
};

static const NSUInteger kSystemZoneCount = sizeof(kSystemZones) / sizeof(kSystemZones[0]);

// Cryptex volumes (/System/Cryptexes and children) are sealed, read-only, signed
// IMG4 mounts: never part of the system APFS snapshot, and jailbreak files can
// never appear in them. They must always be read from the live filesystem.
static BOOL IsCryptexZone(NSString* zonePath) {
    return [zonePath isEqualToString:@"/System/Cryptexes"] || [zonePath hasPrefix:@"/System/Cryptexes/"];
}

// Records every directory (canonPath) with its child names into `structure`.
// Descends only into real (non-symlink) directories while `remaining` allows
// (-1 = unlimited). Returns NO if the directory cannot be enumerated.
+ (BOOL)_buildStructure:(NSMutableDictionary*)structure fsPath:(NSString*)fsPath canonPath:(NSString*)canonPath remaining:(NSInteger)remaining {
    NSFileManager* fm = [NSFileManager defaultManager];
    NSArray* entries = [fm contentsOfDirectoryAtPath:fsPath error:NULL];

    if(!entries) {
        return NO;
    }

    NSMutableArray* children = [NSMutableArray arrayWithCapacity:[entries count]];
    [structure setObject:children forKey:[Shadow getStandardizedPath:canonPath]];

    BOOL descend = (remaining < 0 || remaining > 1);
    NSInteger nextRemaining = (remaining < 0) ? -1 : remaining - 1;

    for(NSString* entry in entries) {
        NSString* entryPath = [fsPath stringByAppendingPathComponent:entry];
        [children addObject:entry];

        if(descend) {
            NSString* fileType = [[fm attributesOfItemAtPath:entryPath error:NULL] objectForKey:NSFileType];

            if([fileType isEqualToString:NSFileTypeDirectory]) {
                [self _buildStructure:structure fsPath:entryPath canonPath:[canonPath stringByAppendingPathComponent:entry] remaining:nextRemaining];
            }
        }
    }

    return YES;
}

// Walks all zones at their configured depth limit. Zones that do not exist are
// skipped (not failures). Returns NO if any existing zone failed to enumerate;
// the partial structure is kept for a live-filesystem fallback.
+ (BOOL)_walkStructureZonesWithPrefix:(NSString*)fsPrefix into:(NSMutableDictionary*)structure {
    NSFileManager* fm = [NSFileManager defaultManager];

    for(NSUInteger i = 0; i < kSystemZoneCount; i++) {
        const SystemZone* zone = &kSystemZones[i];
        NSString* zonePath = @(zone->path);
        // Cryptex zones are never part of the snapshot; always walk them live.
        NSString* fsPath = (fsPrefix && !IsCryptexZone(zonePath)) ? [fsPrefix stringByAppendingPathComponent:zonePath] : zonePath;

        if(![fm fileExistsAtPath:fsPath]) {
            continue;
        }

        if(![self _buildStructure:structure fsPath:fsPath canonPath:zonePath remaining:zone->depth]) {
            fprintf(stderr, "warning: SystemRules: failed walking %s, keeping partial structure\n", zone->path);
            return NO;
        }
    }

    return YES;
}

// Collects every entry (files, dirs, symlinks) under fsPath, canonicalized, full depth.
+ (void)_collectPaths:(NSString*)fsPath canonPath:(NSString*)canonPath into:(NSMutableSet*)set {
    NSFileManager* fm = [NSFileManager defaultManager];
    NSArray* entries = [fm contentsOfDirectoryAtPath:fsPath error:NULL];

    if(!entries) {
        return;
    }

    for(NSString* entry in entries) {
        NSString* canon = [Shadow getStandardizedPath:[canonPath stringByAppendingPathComponent:entry]];

        if(IsCryptexZone(canon)) {
            continue;
        }

        NSString* entryPath = [fsPath stringByAppendingPathComponent:entry];
        [set addObject:canon];

        NSString* fileType = [[fm attributesOfItemAtPath:entryPath error:NULL] objectForKey:NSFileType];

        if([fileType isEqualToString:NSFileTypeDirectory]) {
            [self _collectPaths:entryPath canonPath:canon into:set];
        }
    }
}

+ (void)_collectZonePathsWithPrefix:(NSString*)fsPrefix into:(NSMutableSet*)set {
    NSFileManager* fm = [NSFileManager defaultManager];

    for(NSUInteger i = 0; i < kSystemZoneCount; i++) {
        const SystemZone* zone = &kSystemZones[i];
        NSString* zonePath = @(zone->path);

        if(IsCryptexZone(zonePath)) {
            continue;
        }

        NSString* fsPath = fsPrefix ? [fsPrefix stringByAppendingPathComponent:zonePath] : zonePath;

        if(![fm fileExistsAtPath:fsPath]) {
            continue;
        }

        [self _collectPaths:fsPath canonPath:zonePath into:set];
    }
}

// Full-depth diff walk: entries absent from the snapshot set are classified as
// exact-file or dir blacklist entries. Symlinked dirs are never descended.
+ (void)_diffWalk:(NSString*)fsPath canonPath:(NSString*)canonPath snapshotSet:(NSSet*)snapshotSet exact:(NSMutableArray*)exact dirs:(NSMutableArray*)dirs {
    NSFileManager* fm = [NSFileManager defaultManager];
    NSArray* entries = [fm contentsOfDirectoryAtPath:fsPath error:NULL];

    if(!entries) {
        return;
    }

    for(NSString* entry in entries) {
        NSString* canon = [Shadow getStandardizedPath:[canonPath stringByAppendingPathComponent:entry]];

        if(IsCryptexZone(canon)) {
            continue;
        }

        NSString* entryPath = [fsPath stringByAppendingPathComponent:entry];
        NSString* fileType = [[fm attributesOfItemAtPath:entryPath error:NULL] objectForKey:NSFileType];
        BOOL isDir = [fileType isEqualToString:NSFileTypeDirectory];

        if(![snapshotSet containsObject:canon]) {
            if(isDir) {
                [dirs addObject:canon];
            } else {
                [exact addObject:canon];
            }
        }

        if(isDir) {
            [self _diffWalk:entryPath canonPath:canon snapshotSet:snapshotSet exact:exact dirs:dirs];
        }
    }
}

+ (void)_diffZonesWithPrefix:(NSString*)fsPrefix snapshotSet:(NSSet*)snapshotSet exact:(NSMutableArray*)exact dirs:(NSMutableArray*)dirs {
    NSFileManager* fm = [NSFileManager defaultManager];

    for(NSUInteger i = 0; i < kSystemZoneCount; i++) {
        const SystemZone* zone = &kSystemZones[i];
        NSString* zonePath = @(zone->path);

        if(IsCryptexZone(zonePath)) {
            continue;
        }

        NSString* fsPath = fsPrefix ? [fsPrefix stringByAppendingPathComponent:zonePath] : zonePath;

        if(![fm fileExistsAtPath:fsPath]) {
            continue;
        }

        [self _diffWalk:fsPath canonPath:zonePath snapshotSet:snapshotSet exact:exact dirs:dirs];
    }
}

// Finds a system-volume snapshot name from the volume-root directory fd.
// fs_snapshot_list/mount expect a VOLUME fd (the volume root directory), not a
// raw /dev/disk* character device. Rootful: / IS the system volume root, so
// open("/", O_DIRECTORY) is the volume. Leaves the fd open in *outFd (caller
// closes); returns nil (fail soft) if the volume root cannot be opened or the
// list call fails.
+ (NSString*)_findSnapshotNameWithFd:(int*)outFd {
    int fd = open("/", O_RDONLY | O_DIRECTORY);

    if(fd < 0) {
        return nil;
    }

    // fs_snapshot_list(2) is getattrlistbulk(2) with FSOPT_LIST_SNAPSHOTS:
    // the attrlist MUST request the name (RETURNED_ATTRS comes first in the
    // record), and the buffer holds variable-length records — uint32 length,
    // attrgroup_t returned attrs, attrreference_t name — NOT the adjacent
    // length/string pairs of a raw list.
    struct attrlist attrlist;
    memset(&attrlist, 0, sizeof(attrlist));
    attrlist.bitmapcount = ATTR_BIT_MAP_COUNT;
    attrlist.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME;

    char buf[4096];
    int ret = fs_snapshot_list(fd, &attrlist, buf, sizeof(buf), 0);

    if(ret < 0) {
        close(fd);
        return nil;
    }

    // ret is the RECORD COUNT, not a byte count: never use it as a byte
    // bound. The walk is bounded by the buffer itself plus an iteration
    // cap, so a malformed length can neither overrun nor spin.
    NSMutableArray* names = [NSMutableArray new];
    uint32_t offset = 0;
    const uint32_t kMaxRecords = 4096;

    for(uint32_t record = 0; record < kMaxRecords && (size_t)offset + sizeof(uint32_t) <= sizeof(buf); record++) {
        uint32_t recLen;
        memcpy(&recLen, buf + offset, sizeof(recLen));

        // Minimum record: length + returned attrs + attrreference header.
        if(recLen < 12 || (uint64_t)offset + recLen > sizeof(buf)) {
            break;
        }

        // nameRef sits at offset+8 (after the length and returned attrs);
        // attr_dataoffset is relative to the START of the attrreference.
        attrreference_t nameRef;
        memcpy(&nameRef, buf + offset + 8, sizeof(nameRef));

        if(nameRef.attr_dataoffset < (int32_t)sizeof(nameRef)) {
            break;
        }

        // The NUL-terminated name string must fit inside the record.
        uint32_t nameOffset = (uint32_t)nameRef.attr_dataoffset;

        if(nameOffset + 1 > recLen - 8) {
            break;
        }

        const char* nameStr = buf + offset + 8 + nameOffset;
        uint32_t strMax = recLen - 8 - nameOffset;
        size_t nameLen = strnlen(nameStr, strMax);

        if(nameLen == strMax) {
            break; // no NUL within the record: malformed
        }

        // Reject non-UTF8 garbage instead of inserting it.
        NSString* name = [[NSString alloc] initWithBytes:nameStr length:nameLen encoding:NSUTF8StringEncoding];

        if(name && [name length] > 0) {
            [names addObject:name];
        }

        offset += recLen;
    }

    NSString* chosen = nil;

    for(NSString* name in names) {
        if([name containsString:@"com.apple.os.update"]) {
            chosen = name;
            break;
        }
    }

    if(!chosen && [names count] > 0) {
        chosen = [names objectAtIndex:0];
    }

    if(chosen) {
        *outFd = fd;
        return chosen;
    }

    close(fd);
    return nil;
}

// ProductVersion from SystemVersion.plist; "unknown" if unreadable.
+ (NSString*)_currentiOSVersion {
    NSDictionary* systemVersion = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    NSString* version = [systemVersion objectForKey:@"ProductVersion"];
    return version ? version : @"unknown";
}

// The device state the generated ruleset is a function of: iOS version always,
// plus the current system snapshot name when rootful. Regeneration is skipped
// when this matches the previously generated ruleset.
+ (NSDictionary*)_currentRulesetIdentity {
    NSMutableDictionary* identity = [NSMutableDictionary dictionaryWithObject:[self _currentiOSVersion] forKey:@"iOSVersion"];

    if(![RootBridge isJBRootless]) {
        int fd = -1;
        NSString* snapshotName = [self _findSnapshotNameWithFd:&fd];

        if(snapshotName && fd >= 0) {
            [identity setObject:snapshotName forKey:@"SnapshotName"];
        }

        if(fd >= 0) {
            close(fd);
        }
    }

    return identity;
}

+ (NSDictionary*)generateSystemRuleset {
    NSFileManager* fm = [NSFileManager defaultManager];
    NSMutableDictionary* structure = [NSMutableDictionary new];
    NSMutableArray* exact = [NSMutableArray new];
    NSMutableArray* dirs = [NSMutableArray new];

    BOOL snapshotUsed = NO;
    BOOL snapshotWalkOK = NO;
    NSString* snapshotNameUsed = nil;

    if(![RootBridge isJBRootless]) {
        int fd = -1;
        NSString* snapshotName = [self _findSnapshotNameWithFd:&fd];

        if(snapshotName && fd >= 0) {
            NSString* mountpoint = [RootBridge getJBPath:@"/tmp/ShadowSnapshot"];
            [fm createDirectoryAtPath:mountpoint withIntermediateDirectories:YES attributes:nil error:NULL];

            BOOL mounted = (fs_snapshot_mount(fd, [mountpoint UTF8String], [snapshotName UTF8String], 0) == 0);

            if(mounted) {
                snapshotUsed = YES;
                snapshotNameUsed = snapshotName;

                // Structure comes from the stock snapshot; a partial walk falls back to live below.
                snapshotWalkOK = [self _walkStructureZonesWithPrefix:mountpoint into:structure];

                // Diff: live zones (full depth) minus snapshot zones (full depth).
                NSMutableSet* snapshotSet = [NSMutableSet new];
                [self _collectZonePathsWithPrefix:mountpoint into:snapshotSet];

                if([snapshotSet count] > 0) {
                    [self _diffZonesWithPrefix:nil snapshotSet:snapshotSet exact:exact dirs:dirs];
                } else {
                    fprintf(stderr, "warning: SystemRules: snapshot walk returned nothing, skipping diff\n");
                }
            } else {
                fprintf(stderr, "warning: SystemRules: failed to mount snapshot, using live filesystem\n");
            }

            if(mounted) {
                unmount([mountpoint UTF8String], MNT_FORCE);
                rmdir([mountpoint UTF8String]);
            }

            close(fd);
        } else {
            fprintf(stderr, "warning: SystemRules: no usable system snapshot, using live filesystem\n");
        }
    }

    if(snapshotUsed && !snapshotWalkOK) {
        fprintf(stderr, "warning: SystemRules: partial snapshot walk, falling back to live filesystem\n");
        snapshotUsed = NO;
    }

    BOOL liveWalkOK = YES;

    if(!snapshotUsed) {
        liveWalkOK = [self _walkStructureZonesWithPrefix:nil into:structure];
    }

    if(!liveWalkOK || [structure count] == 0) {
        fprintf(stderr, "error: SystemRules: failed to walk system zones\n");
        return nil;
    }

    NSDateFormatter* formatter = [NSDateFormatter new];
    [formatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ssZ"];

    NSMutableDictionary* ruleset_info = [NSMutableDictionary dictionaryWithDictionary:@{
        @"Name": @"System Rules (generated)",
        @"Author": @"Shadow Service",
        @"GeneratedAt": [formatter stringFromDate:[NSDate date]],
        @"iOSVersion": [self _currentiOSVersion]
    }];

    if(snapshotNameUsed) {
        [ruleset_info setObject:snapshotNameUsed forKey:@"SnapshotName"];
    }

    NSMutableDictionary* ruleset = [NSMutableDictionary new];
    [ruleset setObject:ruleset_info forKey:@"RulesetInfo"];
    [ruleset setObject:structure forKey:@"FileSystemStructure"];

    if([exact count] > 0 || [dirs count] > 0) {
        // Overlapping zones (/System vs /System/Library) produce duplicates; dedupe before the cap.
        exact = [[[NSSet setWithArray:exact] allObjects] mutableCopy];
        dirs = [[[NSSet setWithArray:dirs] allObjects] mutableCopy];

        [exact sortUsingSelector:@selector(compare:)];
        [dirs sortUsingSelector:@selector(compare:)];

        NSInteger total = [exact count] + [dirs count];

        if(total > 5000) {
            fprintf(stderr, "warning: SystemRules: diff produced %ld entries, truncating to 5000\n", (long)total);

            if([exact count] >= 5000) {
                [exact removeObjectsInRange:NSMakeRange(5000, [exact count] - 5000)];
                [dirs removeAllObjects];
            } else {
                NSInteger room = 5000 - [exact count];
                [dirs removeObjectsInRange:NSMakeRange(room, [dirs count] - room)];
            }
        }

        if([exact count] > 0) {
            [ruleset setObject:exact forKey:@"BlacklistExactPaths"];
        }

        if([dirs count] > 0) {
            [ruleset setObject:dirs forKey:@"BlacklistPaths"];
        }
    }

    return ruleset;
}

+ (NSInteger)writeSystemRuleset {
    NSString* path = [RootBridge getJBPath:@SHADOW_RULESETS "/SystemRules.plist"];

    // Read the previous ruleset once: used for the up-to-date gate below and
    // for the snapshot-change/degradation warnings after regeneration.
    NSDictionary* previous = [NSDictionary dictionaryWithContentsOfFile:path];
    NSDictionary* previousInfo = [previous objectForKey:@"RulesetInfo"];
    NSString* previousSnapshot = [previousInfo objectForKey:@"SnapshotName"];
    NSString* previousVersion = [previousInfo objectForKey:@"iOSVersion"];

    NSDictionary* identity = [self _currentRulesetIdentity];
    NSString* currentVersion = [identity objectForKey:@"iOSVersion"];
    NSString* currentSnapshot = [identity objectForKey:@"SnapshotName"];

    // Nothing that affects the ruleset changed since the last generation.
    if(previous && [previousVersion isEqualToString:currentVersion]
    && (!currentSnapshot || [previousSnapshot isEqualToString:currentSnapshot])) {
        printf("system ruleset is current, skipping regeneration\n");
        return 0;
    }

    NSDictionary* ruleset = [self generateSystemRuleset];

    if(!ruleset) {
        return -1;
    }

    // Warn if the system snapshot rotated since the last generation (e.g. an
    // iOS update) — the old ruleset may have blacklisted Apple's new files.
    NSString* currentSnapshotUsed = [[ruleset objectForKey:@"RulesetInfo"] objectForKey:@"SnapshotName"];

    if(previousSnapshot && !currentSnapshotUsed) {
        fprintf(stderr, "warning: SystemRules: no system snapshot available (previously '%s'); using live filesystem\n", [previousSnapshot UTF8String]);
    } else if(previousSnapshot && currentSnapshotUsed && ![previousSnapshot isEqualToString:currentSnapshotUsed]) {
        fprintf(stderr, "note: SystemRules: system snapshot changed '%s' -> '%s' (iOS update?); regenerated against the current snapshot\n", [previousSnapshot UTF8String], [currentSnapshotUsed UTF8String]);
    }

    NSFileManager* fm = [NSFileManager defaultManager];

    [fm createDirectoryAtPath:[path stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:NULL];

    return [ruleset writeToFile:path atomically:YES] ? 1 : -1;
}

@end
