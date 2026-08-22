#import "SHDWCapabilities.h"

#import <HookKit.h>
#import <Preferences/Preferences.h>

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
// Hook-group capability matrix. Mirrors ShadowCore.dylib/dylib.x routing:
//   - ObjC-message groups use HookKit's runtime facade — the HK_Library pref
//     never configures them.
//   - C-function groups install on subCFunc (pref-selected or fishhook).
//   - dlopen_internal (Hook_DynamicLibrariesExtra) needs a private-symbol
//     backend.
// The Settings picker already filters substrate/substitute/swift out of
// selection, and every remaining picker lib is C-function-capable, so
// function groups only fail when NO backend exists at all.
//
// Capability kinds come from Shadow/HookConfiguration.h
// (SHDWHookGroupCapabilityKind) — the metadata is the single source of truth
// for which groups need a message/inline backend. The stale
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

    NSString* kind = SHDWHookGroupCapabilityKind(groupID);

    // Not a hook group (BypassStatus/BypassPreset/HK_Library) or a
    // stale+ignored key ("none"): absent from the canonical metadata —
    // never gated.
    if(!kind || [kind isEqualToString:@"none"]) {
        return YES;
    }

    if([kind isEqualToString:@"message"]) {
        return ([HKSubstitutor getAvailableCategories] & HK_CAT_MESSAGE) != 0;
    }

    if([groupID isEqualToString:@"Hook_DynamicLibrariesExtra"]) {
        return ([HKSubstitutor getAvailableCategories] & HK_CAT_PRIVATE_SYMBOL) != 0;
    }

    // C-function groups: any non-Swift backend can run them.
    hookkit_lib_t available = shdw_available_types();
    return (available & ~HK_LIB_SWIFT) != 0;
}

NSString* SHDWHookGroupUnsupportedReason(NSString* groupID) {
    if(!groupID || SHDWHookGroupSupported(groupID)) {
        return nil;
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
