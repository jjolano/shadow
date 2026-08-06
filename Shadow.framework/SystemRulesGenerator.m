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
        NSString* name = [entry lastPathComponent];
        [children addObject:name];

        if(descend) {
            NSString* fileType = [[fm attributesOfItemAtPath:entry error:NULL] objectForKey:NSFileType];

            if([fileType isEqualToString:NSFileTypeDirectory]) {
                [self _buildStructure:structure fsPath:entry canonPath:[canonPath stringByAppendingPathComponent:name] remaining:nextRemaining];
            }
        }
    }

    return YES;
}

// Walks all zones at their configured depth limit. Zones that do not exist are
// skipped; a failed enumeration keeps the partial structure and stops (caller
// warns).
+ (void)_walkStructureZonesWithPrefix:(NSString*)fsPrefix into:(NSMutableDictionary*)structure {
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
            break;
        }
    }
}

// Collects every entry (files, dirs, symlinks) under fsPath, canonicalized, full depth.
+ (void)_collectPaths:(NSString*)fsPath canonPath:(NSString*)canonPath into:(NSMutableSet*)set {
    NSFileManager* fm = [NSFileManager defaultManager];
    NSArray* entries = [fm contentsOfDirectoryAtPath:fsPath error:NULL];

    if(!entries) {
        return;
    }

    for(NSString* entry in entries) {
        NSString* name = [entry lastPathComponent];
        NSString* canon = [Shadow getStandardizedPath:[canonPath stringByAppendingPathComponent:name]];
        [set addObject:canon];

        NSString* fileType = [[fm attributesOfItemAtPath:entry error:NULL] objectForKey:NSFileType];

        if([fileType isEqualToString:NSFileTypeDirectory]) {
            [self _collectPaths:entry canonPath:canon into:set];
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
        NSString* name = [entry lastPathComponent];
        NSString* canon = [Shadow getStandardizedPath:[canonPath stringByAppendingPathComponent:name]];
        NSString* fileType = [[fm attributesOfItemAtPath:entry error:NULL] objectForKey:NSFileType];
        BOOL isDir = [fileType isEqualToString:NSFileTypeDirectory];

        if(![snapshotSet containsObject:canon]) {
            if(isDir) {
                [dirs addObject:canon];
            } else {
                [exact addObject:canon];
            }
        }

        if(isDir) {
            [self _diffWalk:entry canonPath:canon snapshotSet:snapshotSet exact:exact dirs:dirs];
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

// Finds a system-volume snapshot name by scanning /dev/disk* devices.
// Prefers "com.apple.os.update-*", falls back to the first snapshot found.
// Leaves the device fd open in *outFd (caller closes).
+ (NSString*)_findSnapshotNameWithFd:(int*)outFd {
    NSArray* devEntries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/dev" error:NULL];

    for(NSString* devEntry in devEntries) {
        if(![devEntry hasPrefix:@"disk"]) {
            continue;
        }

        NSString* devPath = [@"/dev" stringByAppendingPathComponent:devEntry];
        int fd = open([devPath UTF8String], O_RDONLY);

        if(fd < 0) {
            continue;
        }

        char buf[4096];

        if(fs_snapshot_list(fd, NULL, buf, sizeof(buf), 0) == 0) {
            NSMutableArray* names = [NSMutableArray new];
            uint32_t offset = 0;

            while(offset + sizeof(uint32_t) <= sizeof(buf)) {
                uint32_t nameLength;
                memcpy(&nameLength, buf + offset, sizeof(nameLength));
                offset += sizeof(nameLength);

                if(nameLength == 0) {
                    break;
                }

                if(offset + nameLength > sizeof(buf)) {
                    break;
                }

                [names addObject:[NSString stringWithUTF8String:buf + offset]];
                offset += nameLength;
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
        }

        close(fd);
    }

    return nil;
}

+ (NSDictionary*)generateSystemRuleset {
    NSFileManager* fm = [NSFileManager defaultManager];
    NSMutableDictionary* structure = [NSMutableDictionary new];
    NSMutableArray* exact = [NSMutableArray new];
    NSMutableArray* dirs = [NSMutableArray new];

    BOOL snapshotUsed = NO;

    if(![RootBridge isJBRootless]) {
        int fd = -1;
        NSString* snapshotName = [self _findSnapshotNameWithFd:&fd];

        if(snapshotName && fd >= 0) {
            NSString* mountpoint = [RootBridge getJBPath:@"/tmp/ShadowSnapshot"];
            [fm createDirectoryAtPath:mountpoint withIntermediateDirectories:YES attributes:nil error:NULL];

            if(fs_snapshot_mount(fd, [mountpoint UTF8String], [snapshotName UTF8String], 0) == 0) {
                snapshotUsed = YES;

                // Structure comes from the stock snapshot; walk partial on failure.
                [self _walkStructureZonesWithPrefix:mountpoint into:structure];

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

            unmount([mountpoint UTF8String], MNT_FORCE);
            rmdir([mountpoint UTF8String]);
            close(fd);
        } else {
            fprintf(stderr, "warning: SystemRules: no usable system snapshot, using live filesystem\n");
        }
    }

    if(!snapshotUsed) {
        [self _walkStructureZonesWithPrefix:nil into:structure];
    }

    if([structure count] == 0 && !snapshotUsed) {
        fprintf(stderr, "error: SystemRules: failed to walk system zones\n");
        return nil;
    }

    NSDateFormatter* formatter = [NSDateFormatter new];
    [formatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ssZ"];

    NSMutableDictionary* ruleset = [NSMutableDictionary new];
    [ruleset setObject:@{
        @"Name": @"System Rules (generated)",
        @"Author": @"Shadow Service",
        @"GeneratedAt": [formatter stringFromDate:[NSDate date]]
    } forKey:@"RulesetInfo"];
    [ruleset setObject:structure forKey:@"FileSystemStructure"];

    if([exact count] > 0 || [dirs count] > 0) {
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

+ (BOOL)writeSystemRuleset {
    NSDictionary* ruleset = [self generateSystemRuleset];

    if(!ruleset) {
        return NO;
    }

    NSString* path = [RootBridge getJBPath:@SHADOW_RULESETS "/SystemRules.plist"];
    NSFileManager* fm = [NSFileManager defaultManager];

    [fm createDirectoryAtPath:[path stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:NULL];

    return [ruleset writeToFile:path atomically:NO];
}

@end
