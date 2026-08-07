//
//  ledger.m
//  shadowd
//
//  Write-ahead ledger persistence (extracted VERBATIM from main.m, A6) plus
//  the A1 record format/parse helpers.  No behavior changes.  The on-disk
//  record byte format is "%d|%s|%s|0x%llx|0x%llx" — DO NOT change (existing
//  on-device ledgers must still parse; see the DEBUG self-check at the
//  bottom of this file).
//

#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <string.h>

#include "ledger.h"

// A1 marker helpers (static; defined in the A1 block at the bottom of this
// file, used by the removal scans below).
static NSString *ledger_owner_marker(const char *path, const char *owner);
static NSString *ledger_path_marker(const char *path);

// ---------------------------------------------------------------------------
// Ledger (write-ahead, mayBeHidden semantics; single serial writer)
// ---------------------------------------------------------------------------
//
// Record line:  <state>|<path>|<ownerKey>|<vnodeHex>|<vIdHex>
//   state: 0 = mayBeHidden, 1 = hidden.
// File:     SHADOWLEDGER1\n<bootUUID>\n<record>...
// Durability: write tmp → fsync → rename → fsync dir.
// A recorded entry means "this operation MAY have happened", never "safe to
// skip".  Per-owner records for a path are removed only at successful
// teardown (WAL-conservative: a crash in any release window re-adopts the
// resource and the client re-releases).

NSString *gBootUUID = nil;   // current boot session (ledger key)

bool ledger_wipe(void);   // used by ledger_read's bad-header path

static NSString *ledger_dir(void) {
    static NSString *dir = nil;
    if (!dir) {
        dir = gIsRootless
            ? @"/var/jb/var/mobile/Library/Preferences/me.jjolano.shadowd"
            : @"/var/mobile/Library/Preferences/me.jjolano.shadowd";
    }
    return dir;
}

static NSString *ledger_file_path(void) {
    return [ledger_dir() stringByAppendingPathComponent:@"shadowd.ledger"];
}

static bool fsync_dir(NSString *dir) {
    int dfd = open(dir.UTF8String, O_RDONLY);
    if (dfd < 0) return false;
    bool ok = (fsync(dfd) == 0);
    close(dfd);
    return ok;
}

bool ledger_write_lines(NSString *bootUUID, NSArray<NSString *> *records) {
    NSMutableString *contents = [NSMutableString stringWithString:@"SHADOWLEDGER1\n"];
    if (bootUUID) [contents appendString:bootUUID];
    [contents appendString:@"\n"];
    for (NSString *rec in records) {
        [contents appendString:rec];
        [contents appendString:@"\n"];
    }

    NSString *dir = ledger_dir();
    if (![[NSFileManager defaultManager] fileExistsAtPath:dir]) {
        if (![[NSFileManager defaultManager] createDirectoryAtPath:dir
                                       withIntermediateDirectories:YES
                                                        attributes:@{NSFilePosixPermissions: @0700}
                                                             error:nil]) {
            shdw_log("ledger: failed to create dir %s", dir.UTF8String);
            return false;
        }
    }
    NSString *path = ledger_file_path();
    NSString *tmp = [path stringByAppendingString:@".tmp"];

    int fd = open(tmp.UTF8String, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        shdw_log("ledger: open tmp failed (%s)", strerror(errno));
        return false;
    }
    fchmod(fd, 0600);
    const char *bytes = contents.UTF8String;
    size_t len = strlen(bytes);
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, bytes + off, len - off);
        if (n <= 0) {
            close(fd);
            unlink(tmp.UTF8String);
            shdw_log("ledger: write failed (%s)", strerror(errno));
            return false;
        }
        off += (size_t)n;
    }
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp.UTF8String);
        shdw_log("ledger: fsync failed");
        return false;
    }
    close(fd);
    if (rename(tmp.UTF8String, path.UTF8String) != 0) {
        unlink(tmp.UTF8String);
        shdw_log("ledger: rename failed (%s)", strerror(errno));
        return false;
    }
    // A12: the directory fsync is part of the durability contract — a failed
    // dir fsync must make the write fail (the rename may not be durable).
    if (!fsync_dir(dir)) {
        shdw_log("ledger: dir fsync failed");
        return false;
    }
    return true;
}

NSArray<NSString *> *ledger_read(NSString **outBootUUID) {
    NSString *path = ledger_file_path();
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return @[];
    }
    NSError *err = nil;
    NSString *contents = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:&err];
    if (!contents) {
        shdw_log("ledger: unreadable (%s), treating as empty", err.localizedDescription.UTF8String);
        return @[];
    }
    NSArray<NSString *> *lines = [contents componentsSeparatedByString:@"\n"];
    NSMutableArray<NSString *> *records = [NSMutableArray array];
    NSString *boot = nil;
    for (NSUInteger i = 0; i < lines.count; i++) {
        NSString *line = lines[i];
        if (line.length == 0) continue;
        if (i == 0) {
            // A14: validate the magic header — anything else is not our ledger.
            if (![line isEqualToString:@"SHADOWLEDGER1"]) {
                shdw_log("ledger: bad header (%s) — discarding", line.UTF8String);
                ledger_wipe();
                return @[];
            }
            continue;
        }
        if (i == 1) { boot = line; continue; }
        [records addObject:line];
    }
    if (outBootUUID) *outBootUUID = boot;
    return records;
}

// A12: wipe reports failure — callers must know whether the removal is durable.
bool ledger_wipe(void) {
    NSString *path = ledger_file_path();
    if (unlink(path.UTF8String) != 0) {
        if (errno == ENOENT) return true;   // already gone — durable by definition
        shdw_log("ledger: unlink failed (%s)", strerror(errno));
        return false;
    }
    if (!fsync_dir(ledger_dir())) {
        shdw_log("ledger: dir fsync failed after unlink");
        return false;
    }
    return true;
}

bool ledger_add_record(const char *path, const char *ownerKey, uint64_t vnode, uint64_t vId, int state) {
    NSString *boot = nil;
    NSMutableArray<NSString *> *records = [NSMutableArray arrayWithArray:ledger_read(&boot)];
    if (!boot) boot = gBootUUID;
    [records addObject:ledger_format_record(state, path, ownerKey, vnode, vId)];
    return ledger_write_lines(boot, records);
}

bool ledger_update_record(const char *path, const char *ownerKey, uint64_t vnode, uint64_t vId, int state) {
    NSString *boot = nil;
    NSMutableArray<NSString *> *records = [NSMutableArray arrayWithArray:ledger_read(&boot)];
    if (!boot) boot = gBootUUID;
    NSString *replacement = ledger_format_record(state, path, ownerKey, vnode, vId);
    NSString *prefix = ledger_owner_marker(path, ownerKey);
    BOOL found = NO;
    for (NSUInteger i = 0; i < records.count; i++) {
        if ([records[i] rangeOfString:prefix].location != NSNotFound) {
            records[i] = replacement;
            found = YES;
            break;
        }
    }
    if (!found) [records addObject:replacement];
    return ledger_write_lines(boot, records);
}

bool ledger_remove_path_records(const char *path) {
    NSString *boot = nil;
    NSMutableArray<NSString *> *records = [NSMutableArray arrayWithArray:ledger_read(&boot)];
    if (!boot) boot = gBootUUID;
    NSString *marker = ledger_path_marker(path);
    NSMutableArray<NSString *> *kept = [NSMutableArray array];
    for (NSString *rec in records) {
        if ([rec rangeOfString:marker].location == NSNotFound) {
            [kept addObject:rec];
        }
    }
    if (kept.count == records.count) return true;   // nothing to remove
    if (kept.count == 0) {
        return ledger_wipe();   // A12: propagate durability failure
    }
    return ledger_write_lines(boot, kept);
}

// A21(b): remove ONLY the per-owner record for (path, ownerKey) — used when a
// failed acquire must undo an ownership it added to a shared resource without
// disturbing the other owners' records.
bool ledger_remove_owner_record(const char *path, const char *ownerKey) {
    NSString *boot = nil;
    NSMutableArray<NSString *> *records = [NSMutableArray arrayWithArray:ledger_read(&boot)];
    if (!boot) boot = gBootUUID;
    NSString *marker = ledger_owner_marker(path, ownerKey);
    NSMutableArray<NSString *> *kept = [NSMutableArray array];
    BOOL found = NO;
    for (NSString *rec in records) {
        if ([rec rangeOfString:marker].location != NSNotFound) {
            found = YES;
            continue;
        }
        [kept addObject:rec];
    }
    if (!found) return true;   // nothing to remove
    if (kept.count == 0) {
        return ledger_wipe();
    }
    return ledger_write_lines(boot, kept);
}

// ---------------------------------------------------------------------------
// Boot UUID (ledger key)
// ---------------------------------------------------------------------------

bool get_boot_uuid(char *buf, size_t len) {
    size_t size = len;
    if (sysctlbyname("kern.bootsessionuuid", buf, &size, NULL, 0) != 0) {
        return false;
    }
    buf[size] = '\0';
    // Format is "UUID: <uuid>"
    if (strncmp(buf, "UUID: ", 6) == 0) {
        memmove(buf, buf + 6, strlen(buf + 6) + 1);
    }
    return buf[0] != '\0';
}

// ---------------------------------------------------------------------------
// A1: record format + parse helpers (byte-identical to the old inline form)
// ---------------------------------------------------------------------------

// One format for the on-disk record: <state>|<path>|<ownerKey>|<vnodeHex>|<vIdHex>.
// HARD CONSTRAINT: keep "%d|%s|%s|0x%llx|0x%llx" — existing on-device ledgers
// must still parse (see the DEBUG self-check at the bottom of this file).
NSString *ledger_format_record(int state, const char *path, const char *owner, uint64_t vnode, uint64_t vId) {
    return [NSString stringWithFormat:@"%d|%s|%s|0x%llx|0x%llx", state, path, owner, vnode, vId];
}

// Strict parse (mirrors the old recover loop): exactly 5 '|'-separated fields,
// state exactly "0" or "1" (intValue-style coercion is NOT accepted), vnode/vId
// via sscanf "0x%llx" (both results checked).  Returns false and logs the
// reason; *state/*path/*owner/*vnode/*vId are only set on success.
bool ledger_parse_record(NSString *rec, int *state, NSString **path, NSString **owner, uint64_t *vnode, uint64_t *vId) {
    NSArray<NSString *> *f = [rec componentsSeparatedByString:@"|"];
    if (f.count != 5) {
        shdw_log("ledger: malformed record dropped: %s", rec.UTF8String);
        return false;
    }
    if ([f[0] isEqualToString:@"0"]) {
        *state = 0;
    } else if ([f[0] isEqualToString:@"1"]) {
        *state = 1;
    } else {
        shdw_log("ledger: invalid state '%s' dropped: %s", f[0].UTF8String, rec.UTF8String);
        return false;
    }
    *path = f[1];
    *owner = f[2];
    uint64_t sv = 0, sid = 0;
    if (sscanf(f[3].UTF8String, "0x%llx", &sv) != 1 ||
        sscanf(f[4].UTF8String, "0x%llx", &sid) != 1) {
        shdw_log("ledger: unparseable vnode/vId dropped: %s", rec.UTF8String);
        return false;
    }
    *vnode = sv;
    *vId = sid;
    return true;
}

// Substring markers for the removal scans: "|path|owner|" and "|path|".
static NSString *ledger_owner_marker(const char *path, const char *owner) {
    return [NSString stringWithFormat:@"|%s|%s|", path, owner];
}

static NSString *ledger_path_marker(const char *path) {
    return [NSString stringWithFormat:@"|%s|", path];
}

// ---------------------------------------------------------------------------
// V2: DEBUG-only self-check — the on-disk wire format must not have changed
// ---------------------------------------------------------------------------

#if DEBUG
#import <assert.h>

static void ledger_self_check(void) {
    // The known literal from the plan: format must reproduce it byte-for-byte.
    NSString *literal = @"1|/x|p:1:2|0x3|0x4";
    NSString *formatted = ledger_format_record(1, "/x", "p:1:2", 0x3, 0x4);
    // ...and identically to the pre-refactor inline form.
    NSString *legacyInline = [NSString stringWithFormat:@"%d|%s|%s|0x%llx|0x%llx",
                              1, "/x", "p:1:2", (uint64_t)0x3, (uint64_t)0x4];
    assert([formatted isEqualToString:legacyInline]);
    assert([formatted isEqualToString:literal]);

    // Parse the literal back out.
    int state = -1;
    NSString *path = nil, *owner = nil;
    uint64_t vnode = 0, vId = 0;
    assert(ledger_parse_record(literal, &state, &path, &owner, &vnode, &vId));
    assert(state == 1);
    assert([path isEqualToString:@"/x"]);
    assert([owner isEqualToString:@"p:1:2"]);
    assert(vnode == 0x3 && vId == 0x4);

    // Round-trip a realistic record (allowlist-shaped path, mayBeHidden).
    NSString *rec = ledger_format_record(0, "/var/mobile/Library/Preferences/me.jjolano.shadow.plist",
                                         "123-456-789", 0xFFFFFFF007004000ULL, 0x2a);
    state = -1; path = nil; owner = nil; vnode = 0; vId = 0;
    assert(ledger_parse_record(rec, &state, &path, &owner, &vnode, &vId));
    assert(state == 0);
    assert([path isEqualToString:@"/var/mobile/Library/Preferences/me.jjolano.shadow.plist"]);
    assert([owner isEqualToString:@"123-456-789"]);
    assert(vnode == 0xFFFFFFF007004000ULL && vId == 0x2a);

    // Removal-scan markers (A1).
    assert([ledger_owner_marker("/x", "p:1:2") isEqualToString:@"|/x|p:1:2|"]);
    assert([ledger_path_marker("/x") isEqualToString:@"|/x|"]);

    // Strict parse must reject malformed / invalid-state / unparseable records.
    assert(!ledger_parse_record(@"5|/x|o|0x3|0x4", &state, &path, &owner, &vnode, &vId));
    assert(!ledger_parse_record(@"1|/x|o", &state, &path, &owner, &vnode, &vId));
    assert(!ledger_parse_record(@"1|/x|o|zz|0x4", &state, &path, &owner, &vnode, &vId));
}

__attribute__((constructor))
static void ledger_self_check_ctor(void) {
    @autoreleasepool {
        ledger_self_check();
    }
}
#endif /* DEBUG */
