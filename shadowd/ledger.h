//
//  ledger.h
//  shadowd
//
//  Ledger persistence + record format/parse helpers (A6/A1).  The on-disk
//  record byte format is "%d|%s|%s|0x%llx|0x%llx" — DO NOT change (existing
//  on-device ledgers must still parse; see the DEBUG self-check in ledger.m).
//

#ifndef shadowd_ledger_h
#define shadowd_ledger_h

#import <Foundation/Foundation.h>

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// Daemon logging (defined in main.m).
extern void shdw_log(const char *fmt, ...);

// Set by main(); ledger_dir() keys off it.
extern bool gIsRootless;

// Current boot session (ledger key) — set by main().
extern NSString *gBootUUID;

bool get_boot_uuid(char *buf, size_t len);
NSArray<NSString *> *ledger_read(NSString **outBootUUID);
bool ledger_reload(void);   // test seam: discard the mirror and re-read the file (simulates a fresh boot)
bool ledger_wipe(void);
bool ledger_write_lines(NSString *bootUUID, NSArray<NSString *> *records);
bool ledger_add_record(const char *path, const char *ownerKey, uint64_t vnode, uint64_t vId, int state);
bool ledger_update_record(const char *path, const char *ownerKey, uint64_t vnode, uint64_t vId, int state);
bool ledger_remove_path_records(const char *path);
bool ledger_remove_owner_record(const char *path, const char *ownerKey);

// A1: one format + one parse helper — byte-identical to the old inline form.
NSString *ledger_format_record(int state, const char *path, const char *owner, uint64_t vnode, uint64_t vId);
bool ledger_parse_record(NSString *rec, int *state, NSString **path, NSString **owner, uint64_t *vnode, uint64_t *vId);

#endif /* shadowd_ledger_h */
