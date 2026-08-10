#import "SHDWCapabilities.h"

#import <HookKit.h>
#import <Preferences/Preferences.h>

#import <mach/mach.h>
#import <bootstrap.h>

#import "../../common.h"
#import "../../protocol.h"

#import <Shadow/HookConfiguration.h>

// Daemon reply statuses (mirror shadowd/main.m's SHADOWD_STATUS_*).
#ifndef SHADOWD_STATUS_OK
#define SHADOWD_STATUS_OK      0
#define SHADOWD_STATUS_EPERM   EPERM
#define SHADOWD_STATUS_ENOTSUP ENOTSUP
#define SHADOWD_STATUS_EBUSY   EBUSY
#endif

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
#define SHDW_CACHE_INTERVAL    5.0

static SHDWDaemonState gDaemonState = SHDWDaemonUnavailable;
static CFAbsoluteTime gDaemonStateTime = 0;

SHDWDaemonState shdw_query_daemon_state(void) {
    mach_port_t service_port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, MACH_SERVICE_NAME, &service_port);

    if(kr != KERN_SUCCESS || !MACH_PORT_VALID(service_port)) {
        return SHDWDaemonUnavailable;
    }

    mach_port_t reply_port = MACH_PORT_NULL;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);

    if(kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), service_port);
        return SHDWDaemonUnavailable;
    }

    shadowd_request_t req;
    memset(&req, 0, sizeof(req));

    req.header.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    req.header.msgh_remote_port = service_port;
    req.header.msgh_local_port = MACH_PORT_NULL;
    req.header.msgh_voucher_port = MACH_PORT_NULL;
    req.header.msgh_size = sizeof(req);

    req.msgh_body.msgh_descriptor_count = 1;
    req.replyPort.name = reply_port;
    req.replyPort.disposition = MACH_MSG_TYPE_MAKE_SEND;
    req.replyPort.type = MACH_MSG_PORT_DESCRIPTOR;

    req.magic = SHADOWD_MAGIC;
    req.version = SHADOWD_VERSION;
    req.op = SHADOWD_OP_STATUS;
    req.requestId = 1;

    SHDWDaemonState state = SHDWDaemonUnavailable;

    kr = mach_msg(&req.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof(req), 0, MACH_PORT_NULL, SHDW_STATUS_TIMEOUT_MS, MACH_PORT_NULL);

    if(kr == KERN_SUCCESS) {
        union {
            shadowd_reply_t reply;
            uint8_t buf[sizeof(shadowd_reply_t) + MAX_TRAILER_SIZE];
        } replyBuf;
        memset(&replyBuf, 0, sizeof(replyBuf));

        kr = mach_msg(&replyBuf.reply.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(replyBuf.buf), reply_port, SHDW_STATUS_TIMEOUT_MS, MACH_PORT_NULL);

        if(kr == KERN_SUCCESS) {
            // Drop the send right the daemon's COPY_SEND reply carried.
            if(MACH_PORT_VALID(replyBuf.reply.header.msgh_remote_port)) {
                mach_port_deallocate(mach_task_self(), replyBuf.reply.header.msgh_remote_port);
            }

            if(replyBuf.reply.magic == SHADOWD_MAGIC && replyBuf.reply.version == SHADOWD_VERSION && replyBuf.reply.requestId == req.requestId) {
                switch(replyBuf.reply.status) {
                    case SHADOWD_STATUS_OK:     state = SHDWDaemonReady; break;
                    case SHADOWD_STATUS_EBUSY:  state = SHDWDaemonStarting; break;
                    default:                    state = SHDWDaemonDisabled; break;
                }
            }
        }
    }

    mach_port_deallocate(mach_task_self(), service_port);
    mach_port_destruct(mach_task_self(), reply_port, 0, 0);

    return state;
}

SHDWDaemonState SHDWQueryDaemonState(void) {
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();

    if(now - gDaemonStateTime > SHDW_CACHE_INTERVAL) {
        gDaemonState = shdw_query_daemon_state();
        gDaemonStateTime = now;
    }

    return gDaemonState;
}

// ---------------------------------------------------------------------------
// Hook-group capability matrix. Mirrors ShadowCore.dylib/dylib.x routing:
//   - ObjC-message groups install on subMain (ElleKit/Substrate/Substitute,
//     or native fallback) — the HK_Library pref never configures subMain.
//   - C-function groups install on subCFunc (pref-selected or fishhook).
//   - dlopen_internal (Hook_DynamicLibrariesExtra) needs ElleKit inline.
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

    hookkit_lib_t available = shdw_available_types();

    if(shdw_is_message_group(groupID)) {
        return (available & (HK_LIB_ELLEKIT | HK_LIB_SUBSTRATE | HK_LIB_SUBSTITUTE | HK_LIB_NATIVE)) != 0;
    }

    if([groupID isEqualToString:@"Hook_DynamicLibrariesExtra"]) {
        return (available & HK_LIB_ELLEKIT) != 0;
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
        if([[spec propertyForKey:PSTableCellKey] isEqualToString:@"PSGroupCell"]) {
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
            [reasons addObject:reason];
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
