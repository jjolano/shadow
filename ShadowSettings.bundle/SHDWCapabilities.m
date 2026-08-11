#import "SHDWCapabilities.h"

#import <HookKit.h>
#import <Preferences/Preferences.h>

#import <xpc/xpc.h>

#import "../../common.h"
#import "../../protocol.h"

#import <Shadow/HookConfiguration.h>

// Bundle anchor: C-function header, so a private class carries the bundle
// identity for localizedStringForKey:value:table:.
@interface SHDWCapabilitiesAnchor : NSObject
@end
@implementation SHDWCapabilitiesAnchor
@end

static NSBundle* shdw_bundle(void) {
    return [NSBundle bundleForClass:[SHDWCapabilitiesAnchor class]];
}

static NSString* shdw_localized(NSString* key) {
    return [shdw_bundle() localizedStringForKey:key value:key table:@"Hooks"];
}

// ---------------------------------------------------------------------------
// Daemon krw state (SHADOWD_OP_STATUS), mirroring the vnode.x client: one
// bootstrap lookup, one STATUS request with a reply port, reply validation.
// No retained connection — the Settings process only pings for health.
// ---------------------------------------------------------------------------

#define SHDW_STATUS_TIMEOUT_MS 300
#define SHDW_STATUS_CACHE_SECS  5.0
// "Starting" is transient (a daemon mid-launch), so it never satisfies the
// terminal-state cache: re-query on this short throttle until the daemon
// reports Ready/Unavailable/Disabled.
#define SHDW_STATUS_STARTING_RECHECK_SECS 2.0

static SHDWDaemonState gDaemonState = SHDWDaemonUnavailable;
static CFAbsoluteTime gDaemonStateTime = 0;

SHDWDaemonState shdw_query_daemon_state(void) {
    static xpc_connection_t conn = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        conn = xpc_connection_create_mach_service(MACH_SERVICE_NAME, NULL, 0);
        if (conn) {
            xpc_connection_set_event_handler(conn, ^(xpc_object_t obj) {
                // Daemon restart etc.: the next query reconnects.
            });
            xpc_connection_resume(conn);
        }
    });
    if (!conn) {
        return SHDWDaemonUnavailable;
    }

    shadowd_xpc_request_t req;
    memset(&req, 0, sizeof(req));
    req.magic = SHADOWD_MAGIC;
    req.version = SHADOWD_VERSION;
    req.op = SHADOWD_OP_STATUS;
    req.requestId = 1;

    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_data(msg, "p", &req, sizeof(req));

    __block SHDWDaemonState state = SHDWDaemonUnavailable;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    xpc_connection_send_message_with_reply(conn, msg, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^(xpc_object_t reply) {
        if (xpc_get_type(reply) != XPC_TYPE_ERROR) {
            size_t len = 0;
            const void *data = xpc_dictionary_get_data(reply, "p", &len);
            if (len == sizeof(shadowd_xpc_reply_t)) {
                const shadowd_xpc_reply_t *r = (const shadowd_xpc_reply_t *)data;
                if (r->magic == SHADOWD_MAGIC && r->version == SHADOWD_VERSION && r->requestId == req.requestId) {
                    switch (r->status) {
                        case SHADOWD_STATUS_OK:     state = SHDWDaemonReady; break;
                        case SHADOWD_STATUS_EBUSY:  state = SHDWDaemonStarting; break;
                        default:                    state = SHDWDaemonDisabled; break;
                    }
                }
            }
        }
        dispatch_semaphore_signal(sem);
    });

    // Never block the Settings UI on IPC: bounded wait, then unavailable.
    if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, SHDW_STATUS_TIMEOUT_MS * NSEC_PER_MSEC)) != 0) {
        return SHDWDaemonUnavailable;
    }
    return state;
}

SHDWDaemonState SHDWQueryDaemonState(void) {
    // Cache-first: never block the Settings UI on Mach IPC. The cache is
    // primed by SHDWRefreshDaemonStateAsync:, so the first specifier load
    // renders instantly (unavailable until the refresh lands), then the
    // controller re-applies gating with the fresh state.
    return gDaemonState;
}

// Query once, store the result, then keep re-querying on the Starting
// throttle until the daemon reports a terminal state: the controllers only
// refresh on page load, so a one-shot query would strand the page on a
// cached "Starting" forever (VnodeHiding stays disabled even after the
// daemon becomes ready).
static void shdw_query_daemon_state_async(void (^completion)(SHDWDaemonState state)) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        SHDWDaemonState state = shdw_query_daemon_state();

        dispatch_async(dispatch_get_main_queue(), ^{
            gDaemonState = state;
            gDaemonStateTime = CFAbsoluteTimeGetCurrent();

            if(completion) {
                completion(state);
            }

            if(state == SHDWDaemonStarting) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(SHDW_STATUS_STARTING_RECHECK_SECS * NSEC_PER_SEC)),
                    dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                    shdw_query_daemon_state_async(completion);
                });
            }
        });
    });
}

void SHDWRefreshDaemonStateAsync(void (^completion)(SHDWDaemonState state)) {
    CFAbsoluteTime age = CFAbsoluteTimeGetCurrent() - gDaemonStateTime;

    // Don't re-ping the daemon on every page entry; terminal states barely
    // change during a session. (Fresh queries still land at least this
    // often.) A cached "Starting" is non-terminal: it only satisfies a short
    // throttle, so the follow-up chain keeps advancing the state.
    if(gDaemonState != SHDWDaemonStarting && age < SHDW_STATUS_CACHE_SECS) {
        if(completion) {
            completion(gDaemonState);
        }
        return;
    }

    if(age < SHDW_STATUS_STARTING_RECHECK_SECS) {
        if(completion) {
            completion(gDaemonState);
        }
        return;
    }

    shdw_query_daemon_state_async(completion);
}

// ---------------------------------------------------------------------------
// Hook-group capability matrix. Mirrors ShadowCore.dylib/dylib.x routing:
//   - ObjC-message groups install on subMain (ElleKit/Substrate/Substitute,
//     or native fallback) — the HK_Library pref never configures subMain.
//   - C-function groups install on subCFunc (pref-selected or fishhook).
//   - dlopen_internal (Hook_DynamicLibrariesExtra) needs a private-symbol or
//     message-capable backend (the ordered PRIVATE_SYMBOL → MESSAGE picker).
//   - VnodeHiding needs the daemon with krw ready.
// The Settings picker already filters substrate/substitute/swift out of
// selection, and every remaining picker lib is C-function-capable, so
// function groups only fail when NO backend exists at all.
//
// Capability kinds come from Shadow/HookConfiguration.h
// (SHDWHookGroupCapabilityKind) — the metadata is the single source of truth
// for which groups need a message/inline/daemon backend. The stale
// Hook_FakeMac key maps to "none" there (removed as inert), so it never
// reads as a message group and never grays out.
// ---------------------------------------------------------------------------

static hookkit_lib_t shdw_available_types(void) {
    return [HKSubstitutor getAvailableSubstitutorTypes];
}

// Message-backend requirement per group, from the canonical metadata
// (SHDWHookGroupCapabilityKind): "message" = ObjC-method swizzle groups.
static BOOL shdw_is_message_group(NSString* groupID) {
    return [SHDWHookGroupCapabilityKind(groupID) isEqualToString:@"message"];
}

BOOL SHDWHookGroupSupported(NSString* groupID) {
    if(!groupID) {
        return YES;
    }

    if([groupID isEqualToString:@"VnodeHiding"]) {
        return SHDWQueryDaemonState() == SHDWDaemonReady;
    }

    NSString* kind = SHDWHookGroupCapabilityKind(groupID);

    // Not a hook group (BypassStatus/BypassPreset/HK_Library) or a
    // stale+ignored key ("none"): absent from the canonical metadata —
    // never gated.
    if(!kind || [kind isEqualToString:@"none"]) {
        return YES;
    }

    hookkit_lib_t available = shdw_available_types();

    if([kind isEqualToString:@"message"]) {
        return (available & (HK_LIB_ELLEKIT | HK_LIB_SUBSTRATE | HK_LIB_SUBSTITUTE | HK_LIB_NATIVE)) != 0;
    }

    if([groupID isEqualToString:@"Hook_DynamicLibrariesExtra"]) {
        // dlopen_internal rides the ordered PRIVATE_SYMBOL → MESSAGE picker
        // (dylib.x/HookCoordinator) — mirror that consumer exactly.
        return ([HKSubstitutor getAvailableCategories] & (HK_CAT_PRIVATE_SYMBOL | HK_CAT_MESSAGE)) != 0;
    }

    // C-function groups: any non-Swift backend can run them.
    return (available & ~HK_LIB_SWIFT) != 0;
}

NSString* SHDWHookGroupUnsupportedReason(NSString* groupID) {
    if(!groupID || SHDWHookGroupSupported(groupID)) {
        return nil;
    }

    if([groupID isEqualToString:@"VnodeHiding"]) {
        if(SHDWQueryDaemonState() == SHDWDaemonStarting) {
            return shdw_localized(@"VNODE_STARTING_REASON");
        }
        return shdw_localized(@"VNODE_UNAVAILABLE_REASON");
    }

    if([groupID isEqualToString:@"Hook_DynamicLibrariesExtra"]) {
        return shdw_localized(@"UNSUPPORTED_ELLEKIT_REASON");
    }

    if(shdw_is_message_group(groupID)) {
        return shdw_localized(@"UNSUPPORTED_MSG_REASON");
    }

    return shdw_localized(@"UNSUPPORTED_FUNC_REASON");
}

void SHDWApplyHookGroupGating(NSArray* specifiers) {
    PSSpecifier* currentGroup = nil;
    // PSSpecifier is not NSCopying — pointer-keyed map for group → reasons.
    NSMapTable* groupReasons = [NSMapTable strongToStrongObjectsMapTable];

    for(PSSpecifier* spec in specifiers) {
        // The plist "cell" key is a string ("PSGroupCell"); cellType is an
        // enum whose ordering is private API — compare the raw property.
        // PSTableCellClassKey ("cell") is the plist string; PSTableCellKey
        // ("cellObject") is the RENDERED cell (a UIResponder) — comparing
        // that crashes with isEqualToString: once cells exist (async
        // re-gating pass).
        if([[spec propertyForKey:PSTableCellClassKey] isEqualToString:@"PSGroupCell"]) {
            currentGroup = spec;
            continue;
        }

        NSString* groupID = [spec identifier];
        if(!groupID || SHDWHookGroupSupported(groupID)) {
            continue;
        }

        // Disabled cells render grayed out; the getter/setter stay wired so
        // stored values are never clobbered.
        [spec setProperty:@NO forKey:PSEnabledKey];

        NSString* reason = SHDWHookGroupUnsupportedReason(groupID);

        if(reason && currentGroup) {
            NSMutableArray* reasons = [groupReasons objectForKey:currentGroup];
            if(!reasons) {
                reasons = [NSMutableArray new];
                [groupReasons setObject:reasons forKey:currentGroup];
            }

            // Groups with multiple message/function rows share one reason
            // string — don't repeat it in the footer.
            if(![reasons containsObject:reason]) {
                [reasons addObject:reason];
            }
        }
    }

    for(PSSpecifier* group in groupReasons) {
        NSString* baseKey = [group propertyForKey:PSFooterTextGroupKey];
        NSString* baseText = baseKey ? shdw_localized(baseKey) : @"";
        NSMutableString* footer = [baseText mutableCopy];

        for(NSString* reason in [groupReasons objectForKey:group]) {
            [footer appendFormat:@"\n%@", reason];
        }

        [group setProperty:footer forKey:PSFooterTextGroupKey];
    }
}
