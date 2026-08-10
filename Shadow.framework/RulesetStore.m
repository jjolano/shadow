#import <Shadow/Ruleset.h>
#import <Shadow/Core.h>
#import "RulesetStore.h"

#import "../common.h"
#import <Shadow/JBPath.h>

#import <stdatomic.h>

// Last time the ruleset dir was scanned. Atomic: multiple hook threads race the
// 1s gate, and a plain double lets several of them scan the same interval.
// (There is one store per process — the backend singleton — so a static is
// equivalent to an ivar; kept identical to the old Backend.m gate.)
static _Atomic(double) lastRulesetCheck = 0.0;

@implementation ShadowRulesetSnapshot

+ (instancetype)snapshotWithRulesets:(NSArray<RulesetEngine *>*)rulesets generation:(NSUInteger)generation {
    ShadowRulesetSnapshot* snapshot = [self new];
    snapshot->_rulesets = [rulesets copy];
    snapshot->_generation = generation;
    return snapshot;
}
@end

@implementation ShadowRulesetStore {
    // Published snapshot; swapped as a unit on reload under @synchronized(self).
    ShadowRulesetSnapshot* current;
    // Current ruleset generation; bumped on every snapshot swap (C0-5).
    NSUInteger _generation;
    // Sorted ruleset URLs from the last load; the per-second change check
    // stats these cached URLs instead of re-enumerating + re-sorting the dir.
    // Transferred verbatim from Backend.m INCLUDING the quirk that this list
    // also contains .shadowcache files while the per-file mtime list below
    // only covers non-cache files — index alignment is preserved so the
    // change-detection cadence is byte-for-byte the same as before.
    NSArray<NSURL *>* rulesetURLs;
    double rulesetDirMtime;
    NSArray<NSNumber *>* rulesetFileMtimes;
    // Compiled engines from the last load, keyed by file path -> @[mtime,
    // engine]. A reload only re-reads/compiles the file(s) whose mtime
    // changed; unchanged files reuse their engine from here, so a one-file
    // edit no longer re-unarchives and re-parses every ruleset. Swapped in
    // _loadSnapshot together with the URL/mtime arrays.
    NSDictionary<NSString *, NSArray *>* rulesetEngines;
}

- (instancetype)init {
    if((self = [super init])) {
        current = [self _loadSnapshot];
    }

    return self;
}

- (double)_fileMtime:(NSString *)path {
    NSDictionary* attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    NSDate* mod_date = [attrs fileModificationDate];

    return mod_date ? [mod_date timeIntervalSinceReferenceDate] : 0.0;
}

// Full directory scan + compile pipeline. Verbatim move of Backend.m's
// _loadRulesets (log lines, cache-suffix skip and mtime bookkeeping all
// preserved); wrapped in one immutable snapshot. The snapshot is published by
// the caller (reload); a scan that produced nothing is used as-is on first
// load and rejected by the last-known-good guard in _reloadRulesets.
- (ShadowRulesetSnapshot *)_loadSnapshot {
    // C0-2: these are Shadow's own file reads (dir listing, plist loads,
    // mtime stats). Without the internal scope the tweak's own
    // NSFileManager/NSDictionary hooks would filter them — and once
    // /Library/Shadow is itself a restricted path (C0-5), Shadow would deny
    // itself its own rulesets. The scope flag is read by the hook layer via
    // +[Shadow shdwIsInternalRead]; nested scopes (via _reloadRulesets) are
    // depth-counted in Core.m. NOTE: the macro is a for-loop — the braced
    // body below is what runs inside the scope; the return lives after it
    // (the compiler can't prove the for body executes).
    ShadowRulesetSnapshot* snapshot = nil;

    SHADOW_INTERNAL_SCOPE {

    NSMutableArray<RulesetEngine *>* result = [NSMutableArray new];
    NSMutableArray<NSNumber *>* mtimes = [NSMutableArray new];

    NSFileManager* fm = [NSFileManager defaultManager];
    NSString* dir = JBPath(@SHADOW_RULESETS);

    rulesetDirMtime = [self _fileMtime:dir];

    NSArray* ruleset_urls = [fm contentsOfDirectoryAtURL:[NSURL fileURLWithPath:dir isDirectory:YES] includingPropertiesForKeys:@[] options:0 error:nil];

    if(ruleset_urls) {
        // Sort by file name so both load order and the mtime snapshot are deterministic.
        ruleset_urls = [ruleset_urls sortedArrayUsingComparator:^NSComparisonResult(NSURL* a, NSURL* b) {
            return [[a lastPathComponent] compare:[b lastPathComponent]];
        }];

        rulesetURLs = ruleset_urls;

        // Engines from the previous load: an unchanged file reuses its
        // compiled engine instead of re-unarchiving/re-parsing it, so a
        // single-file edit only re-reads that file.
        NSDictionary* engines = rulesetEngines;
        NSMutableDictionary* nextEngines = [NSMutableDictionary new];

        for(NSURL* url in ruleset_urls) {
            // RulesetEngine's own compiled caches live here too; they are not
            // rulesets, so never track or load them (their rewrites are still
            // caught by the dir-mtime check).
            if([[url lastPathComponent] hasSuffix:kShadowRulesetCacheSuffix]) {
                continue;
            }

            NSString* path = [url path];
            double mtime = [self _fileMtime:path];

            RulesetEngine* ruleset = nil;
            NSArray* previous = [engines objectForKey:path];

            if(previous && [[previous objectAtIndex:0] doubleValue] == mtime) {
                ruleset = [previous objectAtIndex:1];
            } else {
                ruleset = [RulesetEngine rulesetWithURL:url];
            }

            if(ruleset) {
                NSDictionary* info = [[ruleset payloadDictionary] objectForKey:@"RulesetInfo"];

                if(info) {
                    NSLog(@"[Backend] loaded ruleset: '%@' by %@ (%@)", [info objectForKey:@"Name"], [info objectForKey:@"Author"], url);
                } else {
                    NSLog(@"[Backend] loaded ruleset: %@", url);
                }

                [result addObject:ruleset];
                [nextEngines setObject:@[@(mtime), ruleset] forKey:path];
            } else {
                NSLog(@"[Backend] failed to load ruleset: %@", url);
            }

            // Snapshot every file in the dir (all plists load; a stray non-plist is still tracked so its rewrite is caught).
            [mtimes addObject:@(mtime)];
        }

        rulesetEngines = [nextEngines copy];
    }

    rulesetFileMtimes = [mtimes copy];

    // Rulesets were just (re)loaded; don't re-scan on the first decision.
    atomic_store_explicit(&lastRulesetCheck, [NSDate timeIntervalSinceReferenceDate], memory_order_release);
    snapshot = [ShadowRulesetSnapshot snapshotWithRulesets:result generation:_generation];
    }

    return snapshot;
}

// Swaps in a fresh snapshot (1s-gated reload). Last-known-good: a reload that
// produced no rulesets while a previous non-empty snapshot exists keeps the
// previous snapshot — a failed/unreadable rulesets dir must not flip the
// engine into "everything allowed". Generation bumps only on an actual swap,
// so caches keyed on it invalidate exactly when the served data changes.
- (void)_reloadRulesets {
    ShadowRulesetSnapshot* previous = [self currentSnapshot];
    ShadowRulesetSnapshot* fresh = [self _loadSnapshot];

    if([fresh.rulesets count] == 0 && [previous.rulesets count] > 0) {
        NSLog(@"[Backend] rulesets reload produced an empty set; keeping last-known-good snapshot");
        return;
    }

    // C0-5: atomic generation bump — decision caches keyed on it must see the
    // new value immediately. Reloads are serialized by the 1s scan gate, so
    // the swap is single-writer.
    @synchronized(self) {
        _generation += 1;
        current = [ShadowRulesetSnapshot snapshotWithRulesets:fresh.rulesets generation:_generation];
    }
}

- (ShadowRulesetSnapshot *)currentSnapshot {
    @synchronized(self) {
        return current;
    }
}

- (NSUInteger)generation {
    return [[self currentSnapshot] generation];
}

// 1s-gated change check. Verbatim move of Backend.m's _checkRulesetChanges
// (including the index alignment of the per-file mtime scan, see the ivar
// comment above) — the ruleset-reload cadence is unchanged.
- (void)checkForChanges {
    // C0-2: the dir/file mtime stats are Shadow's own reads — see
    // _loadSnapshot. _reloadRulesets nests a _loadSnapshot scope; the depth
    // counter in Core.m keeps the scope busy until this one exits.
    // NOTE: the macro is a for-loop — the braced body is the scope.
    SHADOW_INTERNAL_SCOPE {

    double now = [NSDate timeIntervalSinceReferenceDate];
    double last = atomic_load_explicit(&lastRulesetCheck, memory_order_acquire);

    if(now - last < 1.0) {
        return;
    }

    // Claim this interval; exactly one thread scans per second.
    double expected = last;

    if(!atomic_compare_exchange_strong_explicit(&lastRulesetCheck, &expected, now, memory_order_acq_rel, memory_order_acquire)) {
        return;
    }

    NSString* dir = JBPath(@SHADOW_RULESETS);

    // All ruleset files live directly in this dir and the generated ruleset is
    // written with atomically:YES (rename), so a dir-mtime change catches adds,
    // removes and renames. In-place edits don't touch the dir mtime and are
    // caught by the per-file stats on the cached URL list below.
    if([self _fileMtime:dir] != rulesetDirMtime) {
        [self _reloadRulesets];
        return;
    }

    // Snapshot the URL/mtime arrays under the lock: a concurrent reload
    // (ruleset file changed) swaps both arrays as one unit, so the snapshot
    // stays internally consistent and outlives the iteration.
    NSArray<NSURL*>* urls;
    NSArray<NSNumber*>* mtimes;

    @synchronized(self) {
        urls = rulesetURLs;
        mtimes = rulesetFileMtimes;
    }

    for(NSUInteger i = 0; i < [urls count]; i++) {
        // The mtime list only tracks ruleset files (compiled .shadowcache
        // artifacts are skipped at load), so skip them here too — with cache
        // files present the original misaligned indexing reported a change on
        // every pass, forcing a full reload each second instead of only when
        // a ruleset actually changed.
        if([[[urls objectAtIndex:i] lastPathComponent] hasSuffix:kShadowRulesetCacheSuffix]) {
            continue;
        }

        if([self _fileMtime:[[urls objectAtIndex:i] path]] != [[mtimes objectAtIndex:i] doubleValue]) {
            [self _reloadRulesets];
            return;
        }
    }
    }
}
@end