// Host tests for the production environment policy.

#import <Foundation/Foundation.h>
#import <Shadow/JBPath.h>
#import "../ShadowCore.dylib/policy/EnvironmentPolicy.h"
#import "ranges.h"
#import <string.h>
#import <stdlib.h>

#define CHECK(_cond, _name) do { \
    if(_cond) { gPass++; } else { gFail++; printf("FAIL: %s\n", _name); } \
} while(0)

static int gPass = 0;
static int gFail = 0;

static void testHiddenNames(void) {
    printf("[tests] env policy: hidden variable names\n");

    CHECK(shdw_env_name_hidden("DYLD_INSERT_LIBRARIES"), "DYLD_INSERT_LIBRARIES hidden");
    CHECK(shdw_env_name_hidden("DYLD_LIBRARY_PATH"), "DYLD_LIBRARY_PATH hidden");
    CHECK(shdw_env_name_hidden("DYLD_"), "bare DYLD_ prefix hidden");
    CHECK(shdw_env_name_hidden("JAILBREAKD_SOMETHING"), "JAILBREAKD_* hidden");
    CHECK(shdw_env_name_hidden("_MSSafeMode"), "_MSSafeMode hidden");
    CHECK(shdw_env_name_hidden("_SafeMode"), "_SafeMode hidden");
    CHECK(shdw_env_name_hidden("_SubstituteSafeMode"), "_SubstituteSafeMode hidden");

    CHECK(!shdw_env_name_hidden("DYLD"), "DYLD (no underscore) NOT hidden");
    CHECK(!shdw_env_name_hidden("_MSSafeModeX"), "safe-mode lookalike NOT hidden (exact match)");
    CHECK(!shdw_env_name_hidden("_SafeModeX"), "_SafeModeX NOT hidden");
    CHECK(!shdw_env_name_hidden("PATH"), "PATH not hidden");
    CHECK(!shdw_env_name_hidden("HOME"), "HOME not hidden");
    CHECK(!shdw_env_name_hidden(""), "empty name not hidden");
    CHECK(!shdw_env_name_hidden(NULL), "NULL name not hidden");

    // getenv view is bare-name exact; the entry view carries '='.
    CHECK(!shdw_env_name_hidden("_MSSafeMode="), "getenv view: quoted name with '=' is NOT hidden (bare-name rule)");
    CHECK(shdw_env_entry_hidden("_MSSafeMode=1"), "entry form _MSSafeMode= hidden");
    CHECK(shdw_env_entry_hidden("_MSSafeMode="), "entry form with empty value hidden");
    CHECK(shdw_env_entry_hidden("DYLD_INSERT_LIBRARIES=/x/y.dylib"), "entry form DYLD_ hidden");
    CHECK(shdw_env_entry_hidden("JAILBREAKD_X=1"), "entry form JAILBREAKD_ hidden");
    CHECK(!shdw_env_entry_hidden("_MSSafeModeX=1"), "entry-form lookalike NOT hidden");
    CHECK(!shdw_env_entry_hidden("PATH=/usr/bin"), "PATH entry not hidden");
    CHECK(!shdw_env_entry_hidden(NULL), "NULL entry not hidden");
}

static void testPathSanitizer(void) {
    printf("[tests] env policy: PATH sanitizer\n");

    CHECK(!shdw_is_restricted_root("/private/preboot"), "stock preboot root allowed");
    CHECK(shdw_is_restricted_root("/private/preboot/x"), "preboot descendant restricted");
    CHECK(shdw_is_restricted_root("/private/var/jb/.installed_dopamine"), "private var jb alias restricted");
    CHECK(!shdw_is_restricted_root("/private/var/jb2"), "private var jb prefix boundary allowed");

    char* p = shdw_env_sanitized_path("/usr/bin:/var/jb/bin:/private/preboot/x:/preboot/y:/bin");
    CHECK(strcmp(p, "/usr/bin:/bin") == 0, "all jailbreak components dropped, order preserved");

    CHECK(strcmp(shdw_env_sanitized_path("/usr/bin:/bin"), "/usr/bin:/bin") == 0, "unchanged value returned as-is");
    CHECK(shdw_env_sanitized_path("/usr/bin:/bin") == shdw_env_sanitized_path("/usr/bin:/bin"),
        "unchanged value keeps pointer identity (thread-local lifetime rule)");

    CHECK(strcmp(shdw_env_sanitized_path("/var/jb"), "") == 0, "all components jailbreak -> empty");
    CHECK(strcmp(shdw_env_sanitized_path(":/var/jb"), "") == 0, "empty leading component preserved, jailbreak dropped");
    CHECK(strcmp(shdw_env_sanitized_path(""), "") == 0, "empty value unchanged");

    // entry form
    char* e1 = NULL;
    char* e2 = NULL;
    size_t c1 = 0;
    size_t c2 = 0;

    CHECK(shdw_env_sanitized_path_entry("PATH=/usr/bin:/var/jb/sbin", &e1, &c1)
        && strcmp(e1, "PATH=/usr/bin") == 0, "entry form rebuilt");
    CHECK(shdw_env_sanitized_path_entry("PATH=/usr/bin", &e2, &c2) == NULL, "unchanged entry returns NULL");
    CHECK(shdw_env_sanitized_path_entry("HOME=/x", &e2, &c2) == NULL, "non-PATH entry returns NULL");
    CHECK(shdw_env_sanitized_path_entry("PATH=", &e2, &c2) == NULL, "empty PATH value returns NULL");

    // The drop rule is a RAW prefix match (baseline parity — the
    // pre-rewrite hooks used hasPrefix @"/preboot" with NO path-component
    // boundary): a component that merely starts with /preboot or
    // /private/preboot is dropped too. /prebootX never exists on a stock
    // device, and the old code dropped it, so the policy does.
    CHECK(strcmp(shdw_env_sanitized_path("/prebootX/bin"), "") == 0, "/prebootX dropped (raw prefix rule, like baseline)");
    CHECK(strcmp(shdw_env_sanitized_path("/private/prebootX/bin"), "") == 0, "/private/prebootX dropped (raw prefix rule)");
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
    NSDictionary* out = shdw_env_sanitized_dictionary(input);

    CHECK(out[@"DYLD_INSERT_LIBRARIES"] == nil, "DYLD key removed");
    CHECK(out[@"_MSSafeMode"] == nil, "safe-mode key removed");
    CHECK([out[@"PATH"] isEqualToString:@"/usr/bin"], "PATH sanitized in place");
    CHECK([out[@"HOME"] isEqualToString:@"/var/mobile"], "HOME preserved");
    CHECK([out[@"TERM"] isEqualToString:@"xterm"], "TERM preserved");
    CHECK(out.count == 3, "exactly 3 keys survive");

    // all-jailbreak PATH: key stays present with an empty value
    NSDictionary* out2 = shdw_env_sanitized_dictionary(@{ @"PATH" : @"/var/jb/bin" });
    CHECK(out2[@"PATH"] != nil && [out2[@"PATH"] isEqualToString:@""], "all-dropped PATH keeps the key with empty value");

    // empty PATH value: untouched (both original and filtered identical)
    CHECK([shdw_env_sanitized_dictionary(@{ @"PATH" : @"" })[@"PATH"] isEqualToString:@""], "empty PATH untouched");
}

static void testArgvSanitizer(void) {
    printf("[tests] env policy: NSProcessInfo.arguments view\n");

    NSArray* a = shdw_env_sanitized_argv(@[ @"/app", @"-dylib", @"/tmp/x.dylib", @"arg1", @"arg2" ]);
    CHECK(a.count == 3 && [a[0] isEqualToString:@"/app"] && [a[1] isEqualToString:@"arg1"] && [a[2] isEqualToString:@"arg2"],
        "injection flag + value dropped, order preserved");

    NSArray* b = shdw_env_sanitized_argv(@[ @"/app", @"arg1", @"-insert", @"/y.dylib" ]);
    CHECK(b.count == 2 && [b[1] isEqualToString:@"arg1"], "trailing flag pair dropped");

    NSArray* c = shdw_env_sanitized_argv(@[ @"/app", @"-dylib" ]);
    CHECK(c.count == 1 && [c[0] isEqualToString:@"/app"], "flag at end with no value: value slot skip is bounded");

    NSArray* d = shdw_env_sanitized_argv(@[ @"/app", @"-dylib", @"-insert", @"/usr/bin/ssh" ]);
    CHECK(d.count == 2 && [d[1] isEqualToString:@"/usr/bin/ssh"], "consecutive flags: first flag's value slot skipped unconditionally");

    NSArray* e = shdw_env_sanitized_argv(@[ @"/app", @"/var/jb/bin/tool", @"arg" ]);
    CHECK(e.count == 2 && [e[1] isEqualToString:@"arg"], "restricted-path argument dropped");

    // argv[0] is ALWAYS kept, even when it would classify as restricted
    NSArray* f = shdw_env_sanitized_argv(@[ @"/var/jb/Applications/App.app/App", @"arg" ]);
    CHECK(f.count == 2 && [f[0] isEqualToString:@"/var/jb/Applications/App.app/App"], "argv[0] preserved unconditionally");

    NSArray* g = shdw_env_sanitized_argv(@[ @"/app", @"-load", @"/x", @"/var/jb/a", @"-bundle", @"/b", @"-init", @"/c", @"tail" ]);
    CHECK(g.count == 2 && [g[1] isEqualToString:@"tail"], "every injection flag dropped");
}

static void testSnapshotBuilder(void) {
    printf("[tests] env policy: _NSGetEnviron view\n");

    char raw1[] = "PATH=/usr/bin:/var/jb/bin\0";
    char raw2[] = "DYLD_INSERT_LIBRARIES=/x.dylib\0";
    char raw3[] = "_MSSafeMode=1\0";
    char raw4[] = "HOME=/var/mobile\0";
    char* env[] = { raw1, raw2, raw3, raw4, NULL };

    char*** snap = shdw_env_filtered_snapshot(env);
    CHECK(snap != NULL, "snapshot built");
    CHECK(strcmp((*snap)[0], "PATH=/usr/bin") == 0, "PATH entry sanitized in snapshot");
    CHECK(strcmp((*snap)[1], "HOME=/var/mobile") == 0, "benign entry kept");
    CHECK((*snap)[2] == NULL, "hidden entries dropped; snapshot terminated");

    // snapshot is rebuilt per call: setenv-visible additions appear
    char raw5[] = "TERM=xterm\0";
    char* env2[] = { raw1, raw4, raw5, NULL };
    char*** snap2 = shdw_env_filtered_snapshot(env2);
    CHECK(strcmp((*snap2)[2], "TERM=xterm") == 0, "new variable visible on next call");

    // original entries that need no change pass through by pointer
    CHECK((*snap2)[1] == raw4, "unchanged entries keep their original pointers");
}

static void testCanonicalRuntimeIdentity(void) {
    printf("[tests] caller identity: exact package paths\n");

    CHECK(shdw_is_canonical_shadow_runtime_path("/var/jb/Library/MobileSubstrate/DynamicLibraries/Shadow.dylib"),
        "rootless Shadow stub is canonical");
    CHECK(shdw_is_canonical_shadow_runtime_path("/var/jb/Library/Frameworks/Shadow.framework/Shadow"),
        "rootless Shadow framework is canonical");
    CHECK(shdw_is_canonical_shadow_runtime_path("/var/jb/usr/lib/ShadowCore.dylib"),
        "rootless ShadowCore is canonical");
    CHECK(shdw_is_canonical_shadow_runtime_path("/Library/MobileSubstrate/DynamicLibraries/Shadow.dylib"),
        "rootful Shadow stub is canonical");
    CHECK(shdw_is_canonical_shadow_runtime_path("/Library/Frameworks/Shadow.framework/Shadow"),
        "rootful Shadow framework is canonical");
    CHECK(shdw_is_canonical_shadow_runtime_path("/usr/lib/ShadowCore.dylib"),
        "rootful ShadowCore is canonical");

    const char* physicalRoot = "/private/preboot/test/procursus";
    CHECK(shdw_is_canonical_shadow_runtime_path_under_root("/private/preboot/test/procursus/Library/MobileSubstrate/DynamicLibraries/Shadow.dylib", physicalRoot),
        "resolved rootless Shadow stub is canonical");
    CHECK(shdw_is_canonical_shadow_runtime_path_under_root("/private/preboot/test/procursus/Library/Frameworks/Shadow.framework/Shadow", physicalRoot),
        "resolved rootless Shadow framework is canonical");
    CHECK(shdw_is_canonical_shadow_runtime_path_under_root("/private/preboot/test/procursus/usr/lib/ShadowCore.dylib", physicalRoot),
        "resolved rootless ShadowCore is canonical");

    CHECK(!shdw_is_canonical_shadow_runtime_path("/var/mobile/ShadowCore.dylib"), "copied ShadowCore is external");
    CHECK(!shdw_is_canonical_shadow_runtime_path("/var/jb/usr/lib/ShadowCoreCompat.dylib"), "ShadowCoreCompat lookalike is external");
    CHECK(!shdw_is_canonical_shadow_runtime_path("/var/jb/usr/lib/ShadowCore.dylib.bak"), "prefix lookalike is external");
    CHECK(!shdw_is_canonical_shadow_runtime_path("/var/jb/usr/lib/shadowcore.dylib"), "case variant is external");
    CHECK(!shdw_is_canonical_shadow_runtime_path("/var/mobile/Library/Frameworks/Shadow.framework/Shadow"), "embedded framework is external");
    CHECK(!shdw_is_canonical_shadow_runtime_path("/var/jb/Library/Frameworks/HookKit.framework/HookKit"), "HookKit is external");
    CHECK(!shdw_is_canonical_shadow_runtime_path("/var/jb/usr/lib/libSandy.dylib"), "libSandy is external");
    CHECK(!shdw_is_canonical_shadow_runtime_path_under_root("/private/preboot/test/procursus/usr/lib/ShadowCoreCompat.dylib", physicalRoot),
        "resolved-root prefix lookalike is external");
    CHECK(!shdw_is_canonical_shadow_runtime_path_under_root("/private/preboot/test/procursus/usr/lib/.shadow-hookprobe-identity-run/ShadowCore.dylib", physicalRoot),
        "resolved-root fixture is external");
    CHECK(!shdw_is_canonical_shadow_runtime_path(NULL), "null image is external");
}

int RunPolicyTests(void) {
    @autoreleasepool {
        testHiddenNames();
        testPathSanitizer();
        testDictionarySanitizer();
        testArgvSanitizer();
        testSnapshotBuilder();
        testCanonicalRuntimeIdentity();

        printf("=== policy: %d passed, %d failed\n", gPass, gFail);
        return gFail;
    }
}
