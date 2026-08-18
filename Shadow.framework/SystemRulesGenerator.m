#import <Shadow/SystemRulesGenerator.h>
#import <Shadow/Core+Utilities.h>
#import "Ruleset.h"


#import <MobileCoreServices/LSApplicationWorkspace.h>
#import <MobileCoreServices/LSApplicationProxy.h>

#import <fcntl.h>
#import <string.h>
#import <sys/attr.h>
#import <sys/mount.h>
#import <sys/snapshot.h>
#import <unistd.h>

#import "../common.h"
#import <Shadow/JBPath.h>

extern int fs_snapshot_list(int fd, struct attrlist* alist, void* buf, size_t bufsize, uint32_t flags) __attribute__((weak_import));
extern int fs_snapshot_mount(int fd, const char* dir, const char* name, uint32_t flags) __attribute__((weak_import));

@implementation SystemRulesGenerator (SystemRules)

// Curated-ruleset engine cache for generateInstalledAppsRuleset, keyed by
// file path -> @[mtime, engine]. The harvest re-runs on every app
// install/uninstall event; an unchanged ruleset file reuses its compiled
// engine instead of re-reading and re-compiling every curated ruleset each
// time. The generator is a class-method utility (shadowd calls it directly),
// so a static is the instance.
static NSMutableDictionary* shdwCuratedRulesetEngines = nil;

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

// One zone-iteration pass shared by the walk/collect/diff phases. cryptex:
// live = cryptex zones always walk the live filesystem (they are never part
// of the system snapshot); skip = cryptex zones are excluded entirely.
// Returns NO (aborts the iteration) when a block returns NO.
+ (BOOL)_forEachSystemZone:(NSString*)fsPrefix cryptexLive:(BOOL)cryptexLive block:(BOOL (^)(NSString* zonePath, NSString* fsPath, const SystemZone* zone))block {
    for(NSUInteger i = 0; i < kSystemZoneCount; i++) {
        const SystemZone* zone = &kSystemZones[i];
        NSString* zonePath = @(zone->path);
        BOOL isCryptex = IsCryptexZone(zonePath);

        if(isCryptex && !cryptexLive) {
            continue;
        }

        NSString* fsPath = (fsPrefix && !isCryptex) ? [fsPrefix stringByAppendingPathComponent:zonePath] : zonePath;

        if(![[NSFileManager defaultManager] fileExistsAtPath:fsPath]) {
            continue;
        }

        if(!block(zonePath, fsPath, zone)) {
            return NO;
        }
    }

    return YES;
}

// Walks all zones at their configured depth limit. Zones that do not exist are
// skipped (not failures). Returns NO if any existing zone failed to enumerate;
// the partial structure is kept for a live-filesystem fallback.
+ (BOOL)_walkStructureZonesWithPrefix:(NSString*)fsPrefix into:(NSMutableDictionary*)structure {
    return [self _forEachSystemZone:fsPrefix cryptexLive:YES block:^BOOL(NSString* zonePath, NSString* fsPath, const SystemZone* zone) {
        if(![self _buildStructure:structure fsPath:fsPath canonPath:zonePath remaining:zone->depth]) {
            fprintf(stderr, "warning: SystemRules: failed walking %s, keeping partial structure\n", zone->path);
            return NO;
        }

        return YES;
    }];
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
    [self _forEachSystemZone:fsPrefix cryptexLive:NO block:^BOOL(NSString* zonePath, NSString* fsPath, const SystemZone* zone) {
        (void) zone;
        [self _collectPaths:fsPath canonPath:zonePath into:set];
        return YES;
    }];
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
    [self _forEachSystemZone:fsPrefix cryptexLive:NO block:^BOOL(NSString* zonePath, NSString* fsPath, const SystemZone* zone) {
        (void) zone;
        [self _diffWalk:fsPath canonPath:zonePath snapshotSet:snapshotSet exact:exact dirs:dirs];
        return YES;
    }];
}

// Finds a system-volume snapshot name from the volume-root directory fd.
// fs_snapshot_list/mount expect a VOLUME fd (the volume root directory), not a
// raw /dev/disk* character device. Rootful: / IS the system volume root, so
// open("/", O_DIRECTORY) is the volume. Leaves the fd open in *outFd (caller
// closes); returns nil (fail soft) if the volume root cannot be opened or the
// list call fails.
+ (NSString*)_findSnapshotNameWithFd:(int*)outFd {
    if(!fs_snapshot_list) {
        return nil;
    }

    int fd = open("/", O_RDONLY | O_DIRECTORY);

    if(fd < 0) {
        return nil;
    }

    // fs_snapshot_list(2) is getattrlistbulk(2) with FSOPT_LIST_SNAPSHOTS:
    // the attrlist MUST request the name (RETURNED_ATTRS comes first in the
    // record), and the buffer holds variable-length records — uint32 length,
    // attribute_set_t returned attrs, attrreference_t name — NOT the adjacent
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

    // ret is the NUMBER OF RECORDS returned (not a byte count); 0 = empty.
    // Iterate exactly ret records (capped), keeping the physical buffer
    // bound as a secondary guard; any anomaly fails soft (nil).
    NSMutableArray* names = [NSMutableArray new];
    uint32_t offset = 0;
    const uint32_t kMaxRecords = 4096;

    // Record layout: uint32 length, then an attribute_set_t (the five-field
    // returned-attrs bitmap), then the requested values in order — the name
    // attrreference_t starts at 4 + sizeof(attribute_set_t) = 24.
    const uint32_t kNameRefOffset = (uint32_t)(sizeof(uint32_t) + sizeof(attribute_set_t));
    const uint32_t kMinRecord = kNameRefOffset + (uint32_t)sizeof(attrreference_t) + 1;

    uint32_t recordCount = (ret < (int32_t)kMaxRecords) ? (uint32_t)ret : kMaxRecords;

    for(uint32_t record = 0; record < recordCount; record++) {
        // Secondary guard: the record header must fit in the buffer.
        if((uint64_t)offset + sizeof(uint32_t) > sizeof(buf)) {
            close(fd);
            return nil;
        }

        uint32_t recLen;
        memcpy(&recLen, buf + offset, sizeof(recLen));

        // Minimum record: length + attribute_set_t + attrreference + NUL.
        if(recLen < kMinRecord || (uint64_t)offset + recLen > sizeof(buf)) {
            close(fd);
            return nil;
        }

        // Trust the name reference only if the returned-attrs bitmap says
        // the name attribute was actually returned.
        attribute_set_t returned;
        memcpy(&returned, buf + offset + sizeof(uint32_t), sizeof(returned));

        if(!(returned.commonattr & ATTR_CMN_NAME)) {
            close(fd);
            return nil;
        }

        // nameRef follows the length and attribute_set_t; its
        // attr_dataoffset is relative to the START of the attrreference.
        attrreference_t nameRef;
        memcpy(&nameRef, buf + offset + kNameRefOffset, sizeof(nameRef));

        if(nameRef.attr_dataoffset < (int32_t)sizeof(nameRef)) {
            close(fd);
            return nil;
        }

        // The NUL-terminated name string must fit inside the record.
        uint32_t nameOffset = (uint32_t)nameRef.attr_dataoffset;

        if((uint64_t)nameOffset + 1 > (uint64_t)recLen - kNameRefOffset) {
            close(fd);
            return nil;
        }

        const char* nameStr = buf + offset + kNameRefOffset + nameOffset;

        // Bound the scan by the record tail AND the kernel-reported
        // attribute length; the NUL must be found within the bound.
        size_t avail = recLen - kNameRefOffset - nameOffset;

        if(nameRef.attr_length < avail) {
            avail = nameRef.attr_length;
        }

        size_t nameLen = strnlen(nameStr, avail);

        if(nameLen == avail) {
            close(fd);
            return nil; // no NUL within the bounded name: malformed
        }

        // Reject non-UTF8 garbage instead of inserting it.
        NSString* name = [[NSString alloc] initWithBytes:nameStr length:nameLen encoding:NSUTF8StringEncoding];

        if(name && [name length] > 0) {
            [names addObject:name];
        }

        offset += recLen; // recLen >= kMinRecord: offset strictly advances
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

    if(!JBIsRootless()) {
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

    if(!JBIsRootless()) {
        int fd = -1;
        NSString* snapshotName = [self _findSnapshotNameWithFd:&fd];

        if(snapshotName && fd >= 0) {
            NSString* mountpoint = JBPath(@"/tmp/ShadowSnapshot");
            [fm createDirectoryAtPath:mountpoint withIntermediateDirectories:YES attributes:nil error:NULL];

            BOOL mounted = fs_snapshot_mount &&
                (fs_snapshot_mount(fd, [mountpoint UTF8String], [snapshotName UTF8String], 0) == 0);

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

                // The diff is the snapshot set's last consumer; drop it
                // (hundreds of thousands of strings) before the live
                // fallback/output assembly below.
                snapshotSet = nil;
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

    // Flatten dict-of-dir→children to {dirs, paths} sorted flat arrays: dirs
    // = the structure keys, paths = keys + children. The flat form loads in a
    // fraction of the time (one array of strings vs ~100K dict/array objects),
    // which is what keeps the 25MB SystemRules load inside the app-launch
    // watchdog window.
    NSMutableSet* dirSet = [NSMutableSet setWithArray:[structure allKeys]];
    NSMutableSet* pathSet = [NSMutableSet setWithArray:[structure allKeys]];

    for(NSString* dir in structure) {
        for(NSString* child in [structure objectForKey:dir]) {
            [pathSet addObject:[dir stringByAppendingPathComponent:child]];
        }
    }

    [ruleset setObject:@{
        @"dirs" : [[dirSet allObjects] sortedArrayUsingSelector:@selector(compare:)],
        @"paths" : [[pathSet allObjects] sortedArrayUsingSelector:@selector(compare:)]
    } forKey:@"FileSystemStructure"];

    if([exact count] > 0 || [dirs count] > 0) {
        // Overlapping zones (/System vs /System/Library) produce duplicates; dedupe before the cap.
        exact = [[[NSSet setWithArray:exact] allObjects] mutableCopy];
        dirs = [[[NSSet setWithArray:dirs] allObjects] mutableCopy];

        [exact sortUsingSelector:@selector(compare:)];
        [dirs sortUsingSelector:@selector(compare:)];

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
    NSString* path = JBPath(@SHADOW_RULESETS "/SystemRules.plist");

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

// Installed-apps ruleset (generated): harvests the URL schemes and bundle IDs
// of every installed app that the CURATED rulesets (JailbreakMisc,
// StandardRules, user-supplied) already restrict by path or bundle ID. The
// engine hot-swaps this file like any other ruleset, so a newly installed
// jailbreak app self-maintains its detection surface: path predicate matches
// -> schemes/ID land in this ruleset -> canOpenURL:/openURL:/
// applicationsAvailableForHandlingURLScheme: probes for them are denied.
// Uninstall the app -> the next regeneration drops it.
+ (NSDictionary*)generateInstalledAppsRuleset {
    NSString* dir = JBPath(@SHADOW_RULESETS);
    NSArray* urls = [[NSFileManager defaultManager] contentsOfDirectoryAtURL:[NSURL fileURLWithPath:dir isDirectory:YES] includingPropertiesForKeys:@[] options:0 error:nil];

    // The harvest signal is only the curated rulesets. Generated rulesets
    // (SystemRules, dpkgInstalled, this file — Author "Shadow Service") are
    // excluded: they are broad by design (every dpkg-installed path, every
    // non-snapshot dir), so using them would mark legitimate apps restricted
    // and break their real canOpenURL:/openURL: links.
    NSMutableArray<RulesetEngine*>* curated = [NSMutableArray new];

    if(!shdwCuratedRulesetEngines) {
        shdwCuratedRulesetEngines = [NSMutableDictionary new];
    }

    for(NSURL* url in urls) {
        if([[url lastPathComponent] hasSuffix:kShadowRulesetCacheSuffix]) {
            continue;
        }

        NSString* path = [url path];
        NSDictionary* attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
        double mtime = attrs ? [[attrs fileModificationDate] timeIntervalSinceReferenceDate] : 0.0;

        // Reuse the compiled engine when the file is unchanged since the
        // last harvest; only a changed file is re-read and re-compiled.
        RulesetEngine* ruleset = nil;
        NSArray* previous = [shdwCuratedRulesetEngines objectForKey:path];

        if(previous && [[previous objectAtIndex:0] doubleValue] == mtime) {
            ruleset = [previous objectAtIndex:1];
        } else {
            ruleset = [RulesetEngine rulesetWithURL:url];

            if(ruleset) {
                [shdwCuratedRulesetEngines setObject:@[@(mtime), ruleset] forKey:path];
            }
        }

        if(!ruleset) {
            continue;
        }

        NSDictionary* info = [[ruleset payloadDictionary] objectForKey:@"RulesetInfo"];

        if([[[info objectForKey:@"Author"] lowercaseString] isEqualToString:@"shadow service"]) {
            continue;
        }

        [curated addObject:ruleset];
    }

    NSMutableSet* schemes = [NSMutableSet new];
    NSMutableSet* bundleids = [NSMutableSet new];

    LSApplicationWorkspace* workspace = [LSApplicationWorkspace defaultWorkspace];

    for(LSApplicationProxy* proxy in [workspace allInstalledApplications]) {
        BOOL restricted = NO;

        for(RulesetEngine* ruleset in curated) {
            if([ruleset isPathBlacklisted:[[proxy bundleURL] path]]
            || [ruleset isBundleIDRestricted:[proxy bundleIdentifier]]) {
                restricted = YES;
                break;
            }
        }

        if(!restricted) {
            continue;
        }

        NSString* bundleID = [proxy bundleIdentifier];

        if([bundleID length] > 0) {
            [bundleids addObject:[bundleID lowercaseString]];
        }

        NSDictionary* info = [[NSBundle bundleWithPath:[[proxy bundleURL] path]] infoDictionary];
        NSArray* urltypes = [info objectForKey:@"CFBundleURLTypes"];

        for(id type in urltypes) {
            // A malicious/malformed app can put non-dictionary entries in
            // CFBundleURLTypes; objectForKey: on them would raise.
            if(![type isKindOfClass:[NSDictionary class]]) {
                continue;
            }

            for(id scheme in [type objectForKey:@"CFBundleURLSchemes"]) {
                if([scheme isKindOfClass:[NSString class]] && [scheme length] > 0) {
                    [schemes addObject:[scheme lowercaseString]];
                }
            }
        }
    }

    NSMutableDictionary* ruleset_dict = [NSMutableDictionary dictionaryWithDictionary:@{
        @"RulesetInfo" : @{
            @"Name" : @"Installed Apps (generated)",
            @"Author" : @"Shadow Service"
        }
    }];

    if([schemes count] > 0) {
        [ruleset_dict setObject:[[schemes allObjects] sortedArrayUsingSelector:@selector(compare:)] forKey:@"BlacklistURLSchemes"];
    }

    if([bundleids count] > 0) {
        [ruleset_dict setObject:[[bundleids allObjects] sortedArrayUsingSelector:@selector(compare:)] forKey:@"BlacklistBundleIDs"];
    }

    return ruleset_dict;
}

+ (NSInteger)writeInstalledAppsRuleset {
    NSString* path = JBPath(@SHADOW_RULESETS "/InstalledApps.plist");

    NSDictionary* ruleset = [self generateInstalledAppsRuleset];

    if(!ruleset) {
        return -1;
    }

    // Skip the write when the content is unchanged: the engine reloads on any
    // mtime change, so a no-op write would churn every process's decision
    // caches for nothing. (Deliberately no GeneratedAt timestamp — the
    // content IS the identity, and this equality gate depends on that.)
    NSDictionary* previous = [NSDictionary dictionaryWithContentsOfFile:path];

    if(previous && [previous isEqual:ruleset]) {
        printf("installed-apps ruleset is current, skipping regeneration\n");
        return 0;
    }

    NSFileManager* fm = [NSFileManager defaultManager];

    [fm createDirectoryAtPath:[path stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:NULL];

    return [ruleset writeToFile:path atomically:YES] ? 1 : -1;
}

@end
