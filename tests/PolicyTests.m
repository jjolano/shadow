// Policy tests for the shared hook policy modules (host, no device).
//
// The dylib's policy code (ShadowCore.dylib/policy/*.m) cannot be compiled
// into this harness (it links the iOS-only Shadow/HookKit engine), so this
// file carries SELF-CONTAINED mirrors of the EnvironmentPolicy rules —
// byte-identical semantics, one function per rule, with the mirror mapping
// documented inline. Changing a rule in EnvironmentPolicy.m without
// updating the mirror here is a test failure by design.
//
// RunPolicyTests() is called from the harness (tests/main.m) after the unit
// groups have run; returns the failure count. Self-contained mirrors of the
// EnvironmentPolicy rules — this file must NOT be the link entry point
// (the harness main() lives in main.m).

#import <Foundation/Foundation.h>

#import <string.h>
#import <stdlib.h>

// ---------------------------------------------------------------------------
// Mirrors of ShadowCore.dylib/policy/EnvironmentPolicy.m
// (shdw_env_name_hidden / shdw_env_entry_hidden / shdw_env_sanitized_path /
//  shdw_env_sanitized_path_entry / shdw_env_sanitized_dictionary /
//  shdw_env_sanitized_argv / shdw_env_filtered_snapshot)
// ---------------------------------------------------------------------------

static BOOL mirrorNameHidden(const char* name) {
    if(!name) {
        return NO;
    }

    if(strncmp(name, "DYLD_", 5) == 0 || strncmp(name, "JAILBREAKD_", 11) == 0) {
        return YES;
    }

    if(strcmp(name, "_MSSafeMode") == 0
    || strcmp(name, "_SafeMode") == 0
    || strcmp(name, "_SubstituteSafeMode") == 0) {
        return YES;
    }

    return NO;
}

static BOOL mirrorEntryHidden(const char* var) {
    if(!var) {
        return NO;
    }

    if(strncmp(var, "DYLD_", 5) == 0 || strncmp(var, "JAILBREAKD_", 11) == 0) {
        return YES;
    }

    if(strncmp(var, "_MSSafeMode=", 12) == 0
    || strncmp(var, "_SafeMode=", 10) == 0
    || strncmp(var, "_SubstituteSafeMode=", 20) == 0) {
        return YES;
    }

    return NO;
}

// PATH component rule (shared by the value and entry forms).
static NSString* mirrorSanitizedPathValue(NSString* value) {
    NSArray* parts = [value componentsSeparatedByString:@":"];
    NSMutableArray* kept = [NSMutableArray arrayWithCapacity:parts.count];

    for(NSString* part in parts) {
        if([part hasPrefix:@"/var/jb"]
        || [part hasPrefix:@"/private/preboot"]
        || [part hasPrefix:@"/preboot"]) {
            continue;
        }

        [kept addObject:part];
    }

    return [kept componentsJoinedByString:@":"];
}

// getenv view: returns the original when unchanged, else a sanitized copy
// (mirrored in thread-local storage).
static char* mirrorSanitizedPath(const char* value) {
    NSString* joined = mirrorSanitizedPathValue([NSString stringWithUTF8String:value]);

    if([joined isEqualToString:[NSString stringWithUTF8String:value]]) {
        return (char *) value;
    }

    static _Thread_local char* storage = NULL;
    static _Thread_local size_t capacity = 0;
    size_t len = joined.length + 1;  // mirrors the dylib's UTF-16 length quirk

    if(len > capacity) {
        char* grown = realloc(storage, len);

        if(!grown) {
            return (char *) value;
        }

        storage = grown;
        capacity = len;
    }

    strcpy(storage, joined.UTF8String);
    return storage;
}

// *environ entry form: NULL when unchanged, else a rebuilt "PATH=..." entry
// in caller thread-local storage.
static char* mirrorSanitizedPathEntry(const char* var, char** storage, size_t* capacity) {
    if(!var || strncmp(var, "PATH=", 5) != 0 || var[5] == '\0') {
        return NULL;
    }

    NSString* joined = [NSString stringWithFormat:@"PATH=%@", mirrorSanitizedPathValue([NSString stringWithUTF8String:var + 5])];

    if([joined isEqualToString:[NSString stringWithUTF8String:var]]) {
        return NULL;
    }

    size_t len = [joined lengthOfBytesUsingEncoding:NSUTF8StringEncoding] + 1;

    if(len > *capacity) {
        char* grown = realloc(*storage, len);

        if(!grown) {
            return NULL;
        }

        *storage = grown;
        *capacity = len;
    }

    strcpy(*storage, joined.UTF8String);
    return *storage;
}

// NSProcessInfo.environment view (mirror): hidden keys removed, PATH
// components sanitized.
static NSDictionary* mirrorSanitizedDictionary(NSDictionary* result) {
    NSMutableDictionary* filtered = [result mutableCopy];

    for(NSString* key in [filtered allKeys]) {
        if(mirrorNameHidden(key.UTF8String)) {
            [filtered removeObjectForKey:key];
        }
    }

    NSString* pathValue = filtered[@"PATH"];

    if(pathValue && pathValue.length > 0) {
        NSString* joined = mirrorSanitizedPathValue(pathValue);

        if(![joined isEqualToString:pathValue]) {
            filtered[@"PATH"] = joined;
        }
    }

    return filtered;
}

// -[NSProcessInfo arguments] view (mirror). Restricted-path stand-in: the
// real engine classifies via isPathRestricted:; for these fixtures the
// engine's own high-signal prefixes are restricted.
static BOOL mirrorIsPathRestricted(NSString* p) {
    return [p hasPrefix:@"/var/jb"] || [p hasPrefix:@"/private/preboot"];
}

static NSArray<NSString*>* mirrorSanitizedArgv(NSArray<NSString*>* result) {
    NSMutableArray<NSString*>* filtered = [NSMutableArray arrayWithCapacity:result.count];

    [filtered addObject:result[0]];

    for(NSUInteger i = 1; i < result.count; i++) {
        NSString* arg = result[i];

        if(mirrorIsPathRestricted(arg)) {
            continue;
        }

        if([arg isEqualToString:@"-dylib"]
        || [arg isEqualToString:@"-insert"]
        || [arg isEqualToString:@"-load"]
        || [arg isEqualToString:@"-bundle"]
        || [arg isEqualToString:@"-init"]) {
            if(i + 1 < result.count) {
                i++;
            }

            continue;
        }

        [filtered addObject:arg];
    }

    return filtered;
}

// _NSGetEnviron view (mirror): filtered snapshot with PATH entries
// rewritten via the entry form.
static char*** mirrorFilteredSnapshot(char** raw) {
    static _Thread_local char** filtered = NULL;
    static _Thread_local size_t filtered_capacity = 0;
    static _Thread_local char* path_storage = NULL;
    static _Thread_local size_t path_capacity = 0;

    size_t count = 0;
    while(raw[count]) {
        count++;
    }

    if(filtered_capacity < count + 1) {
        char** grown = realloc(filtered, (count + 1) * sizeof(char *));

        if(!grown) {
            return NULL;
        }

        filtered = grown;
        filtered_capacity = count + 1;
    }

    size_t out = 0;

    for(size_t i = 0; i < count; i++) {
        if(mirrorEntryHidden(raw[i])) {
            continue;
        }

        if(strncmp(raw[i], "PATH=", 5) == 0) {
            char* sanitized = mirrorSanitizedPathEntry(raw[i], &path_storage, &path_capacity);

            if(sanitized) {
                filtered[out++] = sanitized;
                continue;
            }
        }

        filtered[out++] = raw[i];
    }

    filtered[out] = NULL;

    return &filtered;
}

// ---------------------------------------------------------------------------
// Test battery
// ---------------------------------------------------------------------------

#define CHECK(_cond, _name) do { \
    if(_cond) { gPass++; } else { gFail++; printf("FAIL: %s\n", _name); } \
} while(0)

static int gPass = 0;
static int gFail = 0;

static void testHiddenNames(void) {
    printf("[tests] env policy: hidden variable names\n");

    CHECK(mirrorNameHidden("DYLD_INSERT_LIBRARIES"), "DYLD_INSERT_LIBRARIES hidden");
    CHECK(mirrorNameHidden("DYLD_LIBRARY_PATH"), "DYLD_LIBRARY_PATH hidden");
    CHECK(mirrorNameHidden("DYLD_"), "bare DYLD_ prefix hidden");
    CHECK(mirrorNameHidden("JAILBREAKD_SOMETHING"), "JAILBREAKD_* hidden");
    CHECK(mirrorNameHidden("_MSSafeMode"), "_MSSafeMode hidden");
    CHECK(mirrorNameHidden("_SafeMode"), "_SafeMode hidden");
    CHECK(mirrorNameHidden("_SubstituteSafeMode"), "_SubstituteSafeMode hidden");

    CHECK(!mirrorNameHidden("DYLD"), "DYLD (no underscore) NOT hidden");
    CHECK(!mirrorNameHidden("_MSSafeModeX"), "safe-mode lookalike NOT hidden (exact match)");
    CHECK(!mirrorNameHidden("_SafeModeX"), "_SafeModeX NOT hidden");
    CHECK(!mirrorNameHidden("PATH"), "PATH not hidden");
    CHECK(!mirrorNameHidden("HOME"), "HOME not hidden");
    CHECK(!mirrorNameHidden(""), "empty name not hidden");
    CHECK(!mirrorNameHidden(NULL), "NULL name not hidden");

    // getenv view is bare-name exact; the entry view carries '='.
    CHECK(!mirrorNameHidden("_MSSafeMode="), "getenv view: quoted name with '=' is NOT hidden (bare-name rule)");
    CHECK(mirrorEntryHidden("_MSSafeMode=1"), "entry form _MSSafeMode= hidden");
    CHECK(mirrorEntryHidden("_MSSafeMode="), "entry form with empty value hidden");
    CHECK(mirrorEntryHidden("DYLD_INSERT_LIBRARIES=/x/y.dylib"), "entry form DYLD_ hidden");
    CHECK(mirrorEntryHidden("JAILBREAKD_X=1"), "entry form JAILBREAKD_ hidden");
    CHECK(!mirrorEntryHidden("_MSSafeModeX=1"), "entry-form lookalike NOT hidden");
    CHECK(!mirrorEntryHidden("PATH=/usr/bin"), "PATH entry not hidden");
    CHECK(!mirrorEntryHidden(NULL), "NULL entry not hidden");
}

static void testPathSanitizer(void) {
    printf("[tests] env policy: PATH sanitizer\n");

    char* p = mirrorSanitizedPath("/usr/bin:/var/jb/bin:/private/preboot/x:/preboot/y:/bin");
    CHECK(strcmp(p, "/usr/bin:/bin") == 0, "all jailbreak components dropped, order preserved");

    CHECK(strcmp(mirrorSanitizedPath("/usr/bin:/bin"), "/usr/bin:/bin") == 0, "unchanged value returned as-is");
    CHECK(mirrorSanitizedPath("/usr/bin:/bin") == mirrorSanitizedPath("/usr/bin:/bin"),
        "unchanged value keeps pointer identity (thread-local lifetime rule)");

    CHECK(strcmp(mirrorSanitizedPath("/var/jb"), "") == 0, "all components jailbreak -> empty");
    CHECK(strcmp(mirrorSanitizedPath(":/var/jb"), "") == 0, "empty leading component preserved, jailbreak dropped");
    CHECK(strcmp(mirrorSanitizedPath(""), "") == 0, "empty value unchanged");

    // entry form
    char* e1 = NULL;
    char* e2 = NULL;
    size_t c1 = 0;
    size_t c2 = 0;

    CHECK(mirrorSanitizedPathEntry("PATH=/usr/bin:/var/jb/sbin", &e1, &c1)
        && strcmp(e1, "PATH=/usr/bin") == 0, "entry form rebuilt");
    CHECK(mirrorSanitizedPathEntry("PATH=/usr/bin", &e2, &c2) == NULL, "unchanged entry returns NULL");
    CHECK(mirrorSanitizedPathEntry("HOME=/x", &e2, &c2) == NULL, "non-PATH entry returns NULL");
    CHECK(mirrorSanitizedPathEntry("PATH=", &e2, &c2) == NULL, "empty PATH value returns NULL");

    // The drop rule is a RAW prefix match (baseline parity — the
    // pre-rewrite hooks used hasPrefix @"/preboot" with NO path-component
    // boundary): a component that merely starts with /preboot or
    // /private/preboot is dropped too. /prebootX never exists on a stock
    // device, and the old code dropped it, so the policy does.
    CHECK(strcmp(mirrorSanitizedPath("/prebootX/bin"), "") == 0, "/prebootX dropped (raw prefix rule, like baseline)");
    CHECK(strcmp(mirrorSanitizedPath("/private/prebootX/bin"), "") == 0, "/private/prebootX dropped (raw prefix rule)");
}

static void testDictionarySanitizer(void) {
    printf("[tests] env policy: NSProcessInfo.environment view\n");

    NSDictionary* input = @{
        @"DYLD_INSERT_LIBRARIES" : @"/x.dylib",
        @"_MSSafeMode" : @"1",
        @"PATH" : @"/usr/bin:/var/jb/bin",
        @"HOME" : @"/var/mobile",
        @"TERM" : @"xterm",
    };
    NSDictionary* out = mirrorSanitizedDictionary(input);

    CHECK(out[@"DYLD_INSERT_LIBRARIES"] == nil, "DYLD key removed");
    CHECK(out[@"_MSSafeMode"] == nil, "safe-mode key removed");
    CHECK([out[@"PATH"] isEqualToString:@"/usr/bin"], "PATH sanitized in place");
    CHECK([out[@"HOME"] isEqualToString:@"/var/mobile"], "HOME preserved");
    CHECK([out[@"TERM"] isEqualToString:@"xterm"], "TERM preserved");
    CHECK(out.count == 3, "exactly 3 keys survive");

    // all-jailbreak PATH: key stays present with an empty value
    NSDictionary* out2 = mirrorSanitizedDictionary(@{ @"PATH" : @"/var/jb/bin" });
    CHECK(out2[@"PATH"] != nil && [out2[@"PATH"] isEqualToString:@""], "all-dropped PATH keeps the key with empty value");

    // empty PATH value: untouched (both original and filtered identical)
    CHECK([mirrorSanitizedDictionary(@{ @"PATH" : @"" })[@"PATH"] isEqualToString:@""], "empty PATH untouched");
}

static void testArgvSanitizer(void) {
    printf("[tests] env policy: NSProcessInfo.arguments view\n");

    NSArray* a = mirrorSanitizedArgv(@[ @"/app", @"-dylib", @"/tmp/x.dylib", @"arg1", @"arg2" ]);
    CHECK(a.count == 3 && [a[0] isEqualToString:@"/app"] && [a[1] isEqualToString:@"arg1"] && [a[2] isEqualToString:@"arg2"],
        "injection flag + value dropped, order preserved");

    NSArray* b = mirrorSanitizedArgv(@[ @"/app", @"arg1", @"-insert", @"/y.dylib" ]);
    CHECK(b.count == 2 && [b[1] isEqualToString:@"arg1"], "trailing flag pair dropped");

    NSArray* c = mirrorSanitizedArgv(@[ @"/app", @"-dylib" ]);
    CHECK(c.count == 1 && [c[0] isEqualToString:@"/app"], "flag at end with no value: value slot skip is bounded");

    NSArray* d = mirrorSanitizedArgv(@[ @"/app", @"-dylib", @"-insert", @"/z.dylib" ]);
    CHECK(d.count == 2 && [d[1] isEqualToString:@"/z.dylib"], "consecutive flags: first flag's value slot skipped unconditionally");

    NSArray* e = mirrorSanitizedArgv(@[ @"/app", @"/var/jb/bin/tool", @"arg" ]);
    CHECK(e.count == 2 && [e[1] isEqualToString:@"arg"], "restricted-path argument dropped");

    // argv[0] is ALWAYS kept, even when it would classify as restricted
    NSArray* f = mirrorSanitizedArgv(@[ @"/var/jb/Applications/App.app/App", @"arg" ]);
    CHECK(f.count == 2 && [f[0] isEqualToString:@"/var/jb/Applications/App.app/App"], "argv[0] preserved unconditionally");

    NSArray* g = mirrorSanitizedArgv(@[ @"/app", @"-load", @"/x", @"/var/jb/a", @"-bundle", @"/b", @"-init", @"/c", @"tail" ]);
    CHECK(g.count == 2 && [g[1] isEqualToString:@"tail"], "every injection flag dropped");
}

static void testSnapshotBuilder(void) {
    printf("[tests] env policy: _NSGetEnviron view\n");

    char raw1[] = "PATH=/usr/bin:/var/jb/bin\0";
    char raw2[] = "DYLD_INSERT_LIBRARIES=/x.dylib\0";
    char raw3[] = "_MSSafeMode=1\0";
    char raw4[] = "HOME=/var/mobile\0";
    char* env[] = { raw1, raw2, raw3, raw4, NULL };

    char*** snap = mirrorFilteredSnapshot(env);
    CHECK(snap != NULL, "snapshot built");
    CHECK(strcmp((*snap)[0], "PATH=/usr/bin") == 0, "PATH entry sanitized in snapshot");
    CHECK(strcmp((*snap)[1], "HOME=/var/mobile") == 0, "benign entry kept");
    CHECK((*snap)[2] == NULL, "hidden entries dropped; snapshot terminated");

    // snapshot is rebuilt per call: setenv-visible additions appear
    char raw5[] = "TERM=xterm\0";
    char* env2[] = { raw1, raw4, raw5, NULL };
    char*** snap2 = mirrorFilteredSnapshot(env2);
    CHECK(strcmp((*snap2)[2], "TERM=xterm") == 0, "new variable visible on next call");

    // original entries that need no change pass through by pointer
    CHECK((*snap2)[1] == raw4, "unchanged entries keep their original pointers");
}

int RunPolicyTests(void) {
    @autoreleasepool {
        testHiddenNames();
        testPathSanitizer();
        testDictionarySanitizer();
        testArgvSanitizer();
        testSnapshotBuilder();

        printf("=== policy: %d passed, %d failed\n", gPass, gFail);
        return gFail;
    }
}