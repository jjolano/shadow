// Runtime artifact hiding (merged: NSThread+NSException stack filtering, UIImage asset-name hiding).
// Entry functions keep their per-group names — dylib.x's installer table calls them individually.
#import "UniversalHooks.h"

// Stack-filter helpers shared by NSThread and NSException: exception stacks
// leak Shadow/HookKit frames to detectors that trigger or catch exceptions
// and read their stacks (NSThread's own implementation also funnels through
// NSException on some OS versions), so both classes use the same filter.

static NSArray* shdw_filter_return_addresses(NSArray* result) {
    if(result) {
        NSMutableArray* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSNumber* ret_addr in result) {
            if(!shdw_addr_is_restricted([ret_addr pointerValue])) {
                [result_filtered addObject:ret_addr];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

static NSArray* shdw_filter_stack_symbols(NSArray* result) {
    if(result) {
        NSMutableArray* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSString* line in result) {
            // Frame format: "index  image  address  symbol + offset". The
            // address field is the third non-empty whitespace-separated
            // component. Only frames whose address resolves into a
            // restricted image are dropped; unparsable or benign lines are
            // preserved so the caller never gets an empty trace wholesale.
            NSArray<NSString *>* parts = [line componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            NSMutableArray<NSString *>* fields = [NSMutableArray arrayWithCapacity:parts.count];

            for(NSString* part in parts) {
                if(part.length > 0) {
                    [fields addObject:part];
                }
            }

            if(fields.count >= 3 && [fields[2] hasPrefix:@"0x"] && fields[2].length > 2) {
                unsigned long long value = strtoull(fields[2].UTF8String, NULL, 16);

                if(value != 0 && shdw_addr_is_restricted((void *)(uintptr_t)value)) {
                    continue;
                }
            }

            // Reindex the surviving frame: dropping restricted frames leaves
            // gaps in the stock index column ("0,1,3,4"), a trace stock never
            // produces. The new index is the count so far; the leading index
            // token is replaced in place, preserving the frame's spacing and
            // the addresses below it. Also keeps the frames' index sequence
            // aligned 1:1 with the filtered callStackReturnAddresses.
            if(fields.count >= 1) {
                NSString* reindexed = [[NSString stringWithFormat:@"%lu", (unsigned long)result_filtered.count]
                    stringByAppendingString:[line substringFromIndex:fields[0].length]];

                [result_filtered addObject:reindexed];
            } else {
                // Unparsable line: keep it verbatim.
                [result_filtered addObject:line];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

%group shadowhook_NSThread
%hook NSThread
+ (NSArray *)callStackReturnAddresses __attribute__((annotate("hookkit:allow_inherited"))) {
    NSArray* result = %orig;

    if(isCallerExternal() && result) {
        result = shdw_filter_return_addresses(result);
    }

    return result;
}

+ (NSArray *)callStackSymbols __attribute__((annotate("hookkit:allow_inherited"))) {
    NSArray* result = %orig;

    if(isCallerExternal() && result) {
        result = shdw_filter_stack_symbols(result);
    }

    return result;
}
%end

%hook NSException
// Exception stacks leak Shadow/HookKit frames to detectors that trigger or
// catch exceptions and read their stacks; NSThread's own implementation also
// funnels through NSException on some OS versions. Same filter as NSThread.
- (NSArray *)callStackReturnAddresses __attribute__((annotate("hookkit:allow_inherited"))) {
    NSArray* result = %orig;

    if(isCallerExternal() && result) {
        result = shdw_filter_return_addresses(result);
    }

    return result;
}

- (NSArray *)callStackSymbols __attribute__((annotate("hookkit:allow_inherited"))) {
    NSArray* result = %orig;

    if(isCallerExternal() && result) {
        result = shdw_filter_stack_symbols(result);
    }

    return result;
}
%end
%end

void shdw_universal_nsthread(SHDWHookSession* hooks) {
    %init(shadowhook_NSThread);
}

// C0-3 protected-name policy for assets: an image whose basename exactly
// matches one of Shadow's own artifact names (case-insensitive, with or
// without the file extension) is refused. Exact-name only — never substring
// matching. The list mirrors Shadow.framework/Core.m isProtectedImagePath.
static BOOL shdw_imageNameProtected(NSString* name) {
    if(!name || name.length == 0) {
        return NO;
    }

    static NSSet* protectedNames = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        protectedNames = [NSSet setWithArray:@[
            @"shadow.dylib",
            @"shadow.framework",
            @"libsandy.dylib",
            @"hookkit.framework",
            @"substrate",
            @"libsubstrate",
            @"substitute",
            @"libsubstitute",
            @"ellekit",
            @"libellekit"
        ]];
    });

    // No-allocation matching (the old code built lowercaseString /
    // stringByDeletingPathExtension copies per call): an anchored,
    // pattern-length-bounded range search is exact case-insensitive
    // equality, and the extension-stripped variant is name == pattern + "."
    // + extension where the pattern is the LAST dot's prefix — no further
    // dots in the tail and at least one char after the dot (a trailing dot
    // is not an extension, matching stringByDeletingPathExtension).
    for(NSString* protectedName in protectedNames) {
        if(name.length == protectedName.length
        && [name rangeOfString:protectedName options:NSCaseInsensitiveSearch|NSAnchoredSearch].location == 0) {
            return YES;
        }

        if(name.length >= protectedName.length + 2
        && [name rangeOfString:protectedName options:NSCaseInsensitiveSearch|NSAnchoredSearch range:NSMakeRange(0, protectedName.length)].location == 0
        && [name characterAtIndex:protectedName.length] == '.'
        && [name rangeOfString:@"." options:NSLiteralSearch range:NSMakeRange(protectedName.length + 1, name.length - protectedName.length - 1)].location == NSNotFound) {
            return YES;
        }
    }

    return NO;
}

static BOOL shdw_assetRestricted(NSString* name, NSBundle* bundle) {
    if(bundle && [_shadow isProtectedImagePath:[bundle bundlePath]]) {
        return YES;
    }

    return shdw_imageNameProtected(name);
}

%group shadowhook_UIImage
%hook UIImage
- (instancetype)initWithContentsOfFile:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (UIImage *)imageWithContentsOfFile:(NSString *)path __attribute__((annotate("hookkit:allow_inherited"))) {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (UIImage *)imageNamed:(NSString *)name __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_imageNameProtected(name)) {
        return nil;
    }

    return %orig;
}

+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_assetRestricted(name, bundle)) {
        return nil;
    }

    return %orig;
}

+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle compatibleWithTraitCollection:(UITraitCollection *)traitCollection __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_assetRestricted(name, bundle)) {
        return nil;
    }

    return %orig;
}

// id instead of UIImageConfiguration: the type is iOS 13+ and the tweak
// targets iOS 9; selector dispatch only needs the pointer ABI.
+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle withConfiguration:(id)configuration __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_assetRestricted(name, bundle)) {
        return nil;
    }

    return %orig;
}
%end
%end

%group shadowhook_UIImageVariableValue
%hook UIImage
+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle variableValue:(double)value withConfiguration:(id)configuration __attribute__((annotate("hookkit:allow_inherited"))) {
    if(isCallerExternal() && shdw_assetRestricted(name, bundle)) {
        return nil;
    }

    return %orig;
}
%end
%end

void shdw_universal_foundation_uikit(SHDWHookSession* hooks) {
    %init(shadowhook_UIImage);

    if(class_getClassMethod([UIImage class], @selector(imageNamed:inBundle:variableValue:withConfiguration:))) {
        %init(shadowhook_UIImageVariableValue);
    }
}
