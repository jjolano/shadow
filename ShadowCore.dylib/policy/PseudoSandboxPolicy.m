// Pseudo-sandbox policy: per-app fail-closed allowlist ("overlay") evaluated
// alongside the belt. OFF by default (PseudoSandboxEnabled=0). Audit mode
// (strict=NO) records divergence only; strict mode denies paths outside the
// allowlist. The audit ring buffer lives in the Shadow prefs plist under
// PseudoAuditLog (100 newest, dedup path|op per launch, serial queue).
#import "PseudoSandboxPolicy.h"
#import <Shadow.h>
#include <string.h>
#include <pthread.h>

// Mirrors common.h SHADOW_PREFS_PLIST (the suite is the plist path).
#define SHADOW_PREFS_PLIST "/var/mobile/Library/Preferences/me.jjolano.shadow.plist"
#define kPseudoAuditLogKey @"PseudoAuditLog"
#define kPseudoAuditQueue "me.jjolano.shadow.pseudo-audit"
#define kPseudoAuditCap 100

static BOOL _pseudoEnabled = NO;
static BOOL _pseudoStrict = NO;
static pthread_mutex_t _pseudoLock = PTHREAD_MUTEX_INITIALIZER;

#ifndef SHADOW_TEST_HARNESS
// Per-launch dedup of (path|op); only touched on the serial audit queue.
static NSMutableSet* _auditedKeys = nil;
static dispatch_queue_t _auditQueue = nil;
#endif

static BOOL shdwPseudoStockRoot(const char* path) {
    // Stock roots that never hold jailbreak data: paths under these are
    // always allowed by the pseudo-sandbox.
    static const char* kStockRoots[] = {
        "/usr/", "/bin/", "/sbin/", "/Applications/", "/Library/", "/System/", NULL
    };
    for(int i = 0; kStockRoots[i]; i++) {
        if(strncmp(path, kStockRoots[i], strlen(kStockRoots[i])) == 0) return YES;
    }
    return NO;
}

static BOOL shdwPseudoCarveout(const char* path) {
    // Carve-outs: paths the belt must keep visible even though they live
    // outside the stock roots (system prefs, splashboard, /tmp).
    if(strcmp(path, "/var/mobile/Library/Preferences/.GlobalPreferences.plist") == 0) return YES;
    if(strncmp(path, "/var/mobile/Library/Preferences/com.apple.", strlen("/var/mobile/Library/Preferences/com.apple.")) == 0) return YES;
    if(strncmp(path, "/var/mobile/Library/SplashBoard/Snapshots/com.apple.", strlen("/var/mobile/Library/SplashBoard/Snapshots/com.apple.")) == 0) return YES;
    if(strncmp(path, "/tmp/com.apple.", strlen("/tmp/com.apple.")) == 0) return YES;
    return NO;
}

BOOL shdw_pseudo_is_allowed(const char* path) {
    if(!path || !path[0]) return NO;
    if(shdwPseudoStockRoot(path)) return YES;
    if(shdwPseudoCarveout(path)) return YES;
    // Container: the app's own home + bundle are always allowed.
    NSString* home = NSHomeDirectory();
    if(home.length > 0 && strncmp(path, [home fileSystemRepresentation], home.length) == 0) return YES;
    Shadow* shadow = [Shadow sharedInstance];
    NSString* bundle = shadow.bundlePath;
    if(bundle.length > 0 && strncmp(path, [bundle fileSystemRepresentation], bundle.length) == 0) return YES;
    return NO;
}

BOOL shdw_pseudo_should_deny(const char* path) {
    pthread_mutex_lock(&_pseudoLock);
    BOOL enabled = _pseudoEnabled;
    BOOL strict = _pseudoStrict;
    pthread_mutex_unlock(&_pseudoLock);
    if(!enabled) return NO;
    if(!strict) return NO;   // audit mode: never deny, only log
    return !shdw_pseudo_is_allowed(path);
}

BOOL shdw_pseudo_denies_path(const char* path) { return shdw_pseudo_should_deny(path); }
BOOL shdw_pseudo_is_restricted(const char* path) { return shdw_pseudo_should_deny(path); }
BOOL shdw_pseudo_enforce_should_deny(const char* path) { return shdw_pseudo_should_deny(path); }

BOOL shdw_pseudo_enabled(void) {
    pthread_mutex_lock(&_pseudoLock);
    BOOL v = _pseudoEnabled;
    pthread_mutex_unlock(&_pseudoLock);
    return v;
}

BOOL shdw_pseudo_strict(void) {
    pthread_mutex_lock(&_pseudoLock);
    BOOL v = _pseudoStrict;
    pthread_mutex_unlock(&_pseudoLock);
    return v;
}

static void shdwPseudoApplyPrefs(NSDictionary* prefs) {
    pthread_mutex_lock(&_pseudoLock);
    NSNumber* mode = prefs[@"PseudoSandboxMode"];
    if(mode) {
        // Segmented control: 0=Off, 1=Audit, 2=Strict.
        NSInteger m = [mode integerValue];
        _pseudoEnabled = (m >= 1);
        _pseudoStrict = (m >= 2);
    } else {
        // Legacy keys (pre-segment UI / direct prefs).
        _pseudoEnabled = [prefs[@"PseudoSandboxEnabled"] boolValue] || [prefs[@"PseudoSandboxAudit"] boolValue];
        _pseudoStrict = [prefs[@"PseudoSandboxStrict"] boolValue];
    }
    pthread_mutex_unlock(&_pseudoLock);
}

void shdw_pseudo_init(NSDictionary* prefs) {
#ifndef SHADOW_TEST_HARNESS
    static dispatch_once_t once = 0;
    dispatch_once(&once, ^{
        _auditQueue = dispatch_queue_create(kPseudoAuditQueue, DISPATCH_QUEUE_SERIAL);
        _auditedKeys = [NSMutableSet new];
    });
#endif
    shdwPseudoApplyPrefs(prefs);
}

void shdw_pseudo_refresh(NSDictionary* prefs) {
    shdwPseudoApplyPrefs(prefs);
}

void shdw_pseudo_audit_log(const char* path, BOOL belt, const char* op) {
#ifndef SHADOW_TEST_HARNESS
    if(!shdw_pseudo_enabled()) return;
    if(!path || !path[0]) return;
    if(!_auditQueue) return;
    BOOL pseudo = shdw_pseudo_should_deny(path);
    if(belt == pseudo) return;   // no divergence
    NSString* key = [NSString stringWithFormat:@"%s|%s", path, op ?: ""];
    dispatch_async(_auditQueue, ^{
        if([_auditedKeys containsObject:key]) return;   // dedup per launch
        [_auditedKeys addObject:key];
        NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
        NSMutableArray* log = [[defaults arrayForKey:kPseudoAuditLogKey] mutableCopy] ?: [NSMutableArray new];
        if(log.count >= kPseudoAuditCap) {
            [log removeObjectsInRange:NSMakeRange(0, log.count - (kPseudoAuditCap - 1))];
        }
        NSString* verdict = belt ? @"tighten" : @"breakage-risk";
        [log addObject:@{
            @"path" : [NSString stringWithUTF8String:path],
            @"op" : op ? [NSString stringWithUTF8String:op] : @"",
            @"belt" : @(belt),
            @"pseudo" : @(pseudo),
            @"verdict" : verdict,
        }];
        [defaults setObject:log forKey:kPseudoAuditLogKey];
        [defaults synchronize];
    });
#endif
}