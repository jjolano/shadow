#import "Ruleset.h"
#import <Shadow/Core.h>
#import "RulesetStore.h"

#import "../common.h"
#import <Shadow/JBPath.h>

#import <stdatomic.h>

// Last time the ruleset dir was scanned. Atomic: multiple hook threads race the
// 1s gate, and a plain double lets several of them scan the same interval.
// There is one store per process, so a static is equivalent to an ivar.
static _Atomic(double) lastRulesetCheck = 0.0;

// C0-5: the store's generation, mirrored where cross-binary readers can see it
// without an ObjC send (declared in Core.h). Starts at 0; _reloadRulesets bumps
// it in lockstep with _generation.
_Atomic(uint64_t) shdw_ruleset_generation = 0;

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
    // Ruleset path -> mtime from the last load. Keeping each path with its
    // own timestamp avoids parallel-array drift when compiled .shadowcache
    // files sit between rulesets in directory order.
    NSDictionary<NSString *, NSNumber *>* rulesetFileMtimes;
    double rulesetDirMtime;
    // Compiled engines from the last load, keyed by file path -> @[mtime,
    // engine]. A reload only re-reads/compiles the file(s) whose mtime
    // changed; unchanged files reuse their engine from here, so a one-file
    // edit no longer re-unarchives and re-parses every ruleset. Swapped in
    // _loadSnapshot together with the path/mtime map.
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
    // ns mtime: iOS gives ns; host harness may be 1s-granularity but we still store ns
    return mod_date ? [mod_date timeIntervalSince1970] * 1e9 : 0.0;
}

// Full directory scan + compile pipeline, published as one immutable snapshot.
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
    NSMutableDictionary<NSString *, NSNumber *>* mtimes = [NSMutableDictionary new];

    NSFileManager* fm = [NSFileManager defaultManager];
    NSString* dir = JBPath(@SHADOW_RULESETS);

    rulesetDirMtime = [self _fileMtime:dir];

    NSArray* ruleset_urls = [fm contentsOfDirectoryAtURL:[NSURL fileURLWithPath:dir isDirectory:YES] includingPropertiesForKeys:@[] options:0 error:nil];

    if(ruleset_urls) {
        // Sort by file name so both load order and the mtime snapshot are deterministic.
        ruleset_urls = [ruleset_urls sortedArrayUsingComparator:^NSComparisonResult(NSURL* a, NSURL* b) {
            return [[a lastPathComponent] compare:[b lastPathComponent]];
        }];

        // Engines from the previous load: an unchanged file reuses its
        // compiled engine instead of re-unarchiving/re-parsing it, so a
        // single-file edit only re-reads that file.
        NSDictionary* engines = rulesetEngines;
        NSMutableDictionary* nextEngines = [NSMutableDictionary new];

        // prune stale .shadowcache: ruleset .shadowcache without matching plist (ns check via compiler)
        for(NSURL* cUrl in ruleset_urls) {
            if([[cUrl lastPathComponent] hasSuffix:kShadowRulesetCacheSuffix]) {
                NSString *plistPath = [[cUrl path] stringByReplacingOccurrencesOfString:kShadowRulesetCacheSuffix withString:@""];
                if(![[NSFileManager defaultManager] fileExistsAtPath:plistPath]) {
                    @try { [[NSFileManager defaultManager] removeItemAtPath:[cUrl path] error:nil]; } @catch(NSException *e) {}
                }
            }
        }
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
                    NSLog(@"[Shadow] loaded ruleset: '%@' by %@ (%@)", [info objectForKey:@"Name"], [info objectForKey:@"Author"], url);
                } else {
                    NSLog(@"[Shadow] loaded ruleset: %@", url);
                }

                [result addObject:ruleset];
                [nextEngines setObject:@[@(mtime), ruleset] forKey:path];
            } else {
                NSLog(@"[Shadow] failed to load ruleset: %@", url);
            }

            // Snapshot every file in the dir (all plists load; a stray non-plist is still tracked so its rewrite is caught).
            [mtimes setObject:@(mtime) forKey:path];
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
        NSLog(@"[Shadow] rulesets reload produced an empty set; keeping last-known-good snapshot");
        return;
    }

    // C0-5: atomic generation bump — decision caches keyed on it must see the
    // new value immediately. Reloads are serialized by the 1s scan gate, so
    // the swap is single-writer.
    @synchronized(self) {
        _generation += 1;
        current = [ShadowRulesetSnapshot snapshotWithRulesets:fresh.rulesets generation:_generation];
    }

    // Publish the same bump where lock-free readers can see it (Core.h). After
    // the swap, so a reader that observes the new generation is guaranteed the
    // new snapshot is already current.
    atomic_store_explicit(&shdw_ruleset_generation, (uint64_t) _generation, memory_order_release);
}

- (ShadowRulesetSnapshot *)currentSnapshot {
    @synchronized(self) {
        return current;
    }
}

- (NSUInteger)generation {
    return [[self currentSnapshot] generation];
}

// 1s-gated directory and per-file change check.
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

    // Snapshot the path/mtime map so it outlives the iteration.
    NSDictionary<NSString*, NSNumber*>* mtimes;

    @synchronized(self) {
        mtimes = rulesetFileMtimes;
    }

    for(NSString* path in mtimes) {
        if([self _fileMtime:path] != [[mtimes objectForKey:path] doubleValue]) {
            [self _reloadRulesets];
            return;
        }
    }
    }
}
@end
