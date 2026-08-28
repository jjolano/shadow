// Host test for the About pane's update comparison. The controller itself
// needs Preferences.framework, which the harness has no stand-in for, so this
// pins the one piece of logic that can silently go wrong: the NSNumericSearch
// ordering aboutUpdateStatus: reads, over this project's real dpkg versions
// and release tags.

#import <Foundation/Foundation.h>

#define CHECK(_cond, _name) do { \
    if(_cond) { gPass++; } else { gFail++; printf("FAIL: %s\n", _name); } \
} while(0)

static int gPass = 0;
static int gFail = 0;

// Mirrors SHDWAboutListController -aboutUpdateStatus:.
static BOOL outdated(NSString* installed, NSString* latest) {
    return [installed compare:latest options:NSNumericSearch] == NSOrderedAscending;
}

static void testUpdateOrdering(void) {
    printf("[tests] about: installed vs latest ordering\n");

    CHECK(outdated(@"3.7.5", @"3.7.6"), "older patch offers an update");
    CHECK(!outdated(@"3.7.6", @"3.7.6"), "exact match is up to date");
    CHECK(!outdated(@"4.0.0", @"3.7.6"), "dev build ahead of the tag is up to date");
    CHECK(outdated(@"3.6.9-2", @"3.7.6"), "revision does not mask a real upgrade");
    CHECK(outdated(@"3.7.6-1", @"3.7.7"), "revision does not mask a patch upgrade");

    // Tags carry no debian revision, so a revised build of the current
    // release must not read as older than the release it was built from.
    CHECK(!outdated(@"3.5.6-4+debug", @"3.5.6"), "debian revision sorts above its base tag");
    CHECK(!outdated(@"3.5-1", @"3.5"), "shipped 3.5-1 is up to date against tag 3.5");

    // The reason this is NSNumericSearch and not plain compare:.
    CHECK(outdated(@"3.9", @"3.10"), "3.9 is older than 3.10");
    CHECK(!outdated(@"3.10", @"3.9"), "3.10 is newer than 3.9");
}

int RunVersionCompareTests(void) {
    @autoreleasepool {
        testUpdateOrdering();

        printf("=== version compare: %d passed, %d failed\n", gPass, gFail);
        return gFail;
    }
}
