"""Execute settings helpers and Updates controller with host Foundation/doubles.

macOS: python3 tests/verify-settings-behavior.py
Linux: python3 tests/verify-settings-behavior.py --docker <GNUstep image>
The Docker image must already contain clang, libobjc2 and gnustep-config.
"""
import argparse
import platform
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
settings = root / "src/ShadowSettings.bundle"
prefs = (settings / "SHDWPrefs.m").read_text()
about = (settings / "SHDWAboutListController.m").read_text()
updates = (settings / "SHDWUpdatesController.m").read_text()
keys = (root / "src/Shadow.framework/Headers/Shadow/SHDWPlugin.h").read_text()

# Compile the original bodies, not Python translations of their behavior.
helpers = prefs[prefs.index("BOOL SHDWAppFollowsGlobal("):
                prefs.index("UIImage *SHDWSettingsSymbol(")]
parser = updates[updates.index("NSString* version = nil;"):
                 updates.index("strongSelf->latestVersion = version;")]
source = '#import <Foundation/Foundation.h>\n#import <objc/runtime.h>\n#include <assert.h>\n'
source += "\n".join(re.findall(
    r'^#define SHDW(?:AppEnabled|AppDisabled|DetectorAggressive)ID\s+@"[^"]+"',
    keys, re.M))
source += '\nBOOL SHDWAppIsCustomized(id appPrefs);\n' + helpers
source += '#define JBPath(path) (path)\n#define THEOS_PACKAGE_INSTALL_PREFIX "/test-bootstrap"\n'
source += prefs[prefs.index('NSString *SHDWInstalledVersion('):prefs.index('BOOL SHDWAppEnabled(')].replace(
    'SHDWInstalledVersion(void)', 'readInstalledVersion(void)')
source += '''
static NSDictionary *localFiles;
static NSUInteger fileReads;
static BOOL testFileExists(id instance, SEL selector, NSString *path) { return localFiles[path] != nil; }
static id testFileContents(id cls, SEL selector, NSString *path, NSStringEncoding encoding, NSError **error) {
    ++fileReads; return localFiles[path];
}
enum { UIImageRenderingModeAlwaysTemplate = 2 };
@interface UIImage : NSObject
@property(nonatomic) NSInteger renderingMode;
- (UIImage *)imageWithRenderingMode:(NSInteger)mode;
@end
@interface UIImage (ModernSymbols)
+ (UIImage *)systemImageNamed:(NSString *)name;
@end
@implementation UIImage
- (UIImage *)imageWithRenderingMode:(NSInteger)mode { self.renderingMode = mode; return self; }
@end
static id testSymbol(id cls, SEL selector, NSString *name) {
    return [name isEqualToString:@"missing"] ? nil : [UIImage new];
}
'''
source += prefs[prefs.index("UIImage *SHDWSettingsSymbol("):
                prefs.index("void SHDWClearAppEnabled(")]
source += r'''
// Minimal UIKit/Preferences and session doubles execute the real controllers.
typedef struct { double top, left, bottom, right; } UIEdgeInsets;
#define UIEdgeInsetsMake(a,b,c,d) ((UIEdgeInsets){a,b,c,d})
enum { UIViewAutoresizingFlexibleWidth = 1, UIViewAutoresizingFlexibleHeight = 2,
    UITableViewStyleGrouped = 1, UITableViewCellStyleSubtitle = 3,
    UITableViewCellSelectionStyleNone = 0, UITableViewCellSelectionStyleDefault = 1,
    UIAccessibilityTraitButton = 1, UIAccessibilityTraitNotEnabled = 2,
    UIAccessibilityLayoutChangedNotification = 1, UIDataDetectorTypeNone = 0 };
static CGFloat UITableViewAutomaticDimension = -1;
static NSString *UIFontTextStyleBody = @"body", *UIFontTextStyleSubheadline = @"subheadline";
static void UIAccessibilityPostNotification(NSInteger notification, id argument) {}
@interface UIColor : NSObject
+ (id)clearColor; + (id)blackColor; + (id)labelColor;
@end
@implementation UIColor
+ (id)clearColor { return [self new]; }
+ (id)blackColor { return [self new]; }
+ (id)labelColor { return [self new]; }
@end
@interface UIFont : NSObject
+ (id)preferredFontForTextStyle:(NSString *)style;
@end
@implementation UIFont
+ (id)preferredFontForTextStyle:(NSString *)style { return [self new]; }
@end
@interface UIView : NSObject
@property NSRect bounds;
@property NSUInteger autoresizingMask;
@property BOOL userInteractionEnabled, isAccessibilityElement;
@property(nonatomic, strong) UIColor *backgroundColor, *tintColor;
@property(nonatomic, strong) NSMutableArray *subviews;
- (instancetype)initWithFrame:(NSRect)frame;
- (void)addSubview:(id)view;
@end
@implementation UIView
- (instancetype)init { if((self = [super init])) { _bounds = NSMakeRect(0,0,320,640); _subviews = [NSMutableArray new]; } return self; }
- (instancetype)initWithFrame:(NSRect)frame { if((self = [self init])) _bounds = frame; return self; }
- (void)addSubview:(id)view { [_subviews addObject:view]; }
@end
@interface UILabel : UIView
@property NSInteger numberOfLines;
@property BOOL enabled, adjustsFontForContentSizeCategory;
@property(nonatomic, copy) NSString *text;
@property(nonatomic, strong) UIFont *font;
@property(nonatomic, strong) UIColor *textColor;
@end
@implementation UILabel @end
@interface UIImageView : UIView
@property(nonatomic, strong) UIImage *image;
@end
@implementation UIImageView @end
@interface UITextView : UILabel
@property BOOL editable, selectable, scrollEnabled, alwaysBounceVertical;
@property NSInteger dataDetectorTypes;
@property UIEdgeInsets textContainerInset;
@end
@implementation UITextView @end
@interface UITableViewCell : UIView
@property NSInteger selectionStyle, accessibilityTraits;
@property(nonatomic, strong) UILabel *textLabel, *detailTextLabel;
@property(nonatomic, strong) UIView *contentView;
@property(nonatomic, strong) UIImageView *imageView;
- (instancetype)initWithStyle:(NSInteger)style reuseIdentifier:(NSString *)identifier;
@end
@implementation UITableViewCell
- (instancetype)initWithStyle:(NSInteger)style reuseIdentifier:(NSString *)identifier {
    if((self = [super init])) { _textLabel = [UILabel new]; _detailTextLabel = [UILabel new];
        _contentView = [UIView new]; _imageView = [UIImageView new]; } return self;
}
@end
@interface UITableView : UIView
@property(nonatomic, weak) id dataSource, delegate;
@property CGFloat rowHeight, estimatedRowHeight;
- (instancetype)initWithFrame:(NSRect)frame style:(NSInteger)style;
- (void)reloadData;
- (void)deselectRowAtIndexPath:(NSIndexPath *)path animated:(BOOL)animated;
@end
@implementation UITableView
- (instancetype)initWithFrame:(NSRect)frame style:(NSInteger)style { return [super initWithFrame:frame]; }
- (void)reloadData {}
- (void)deselectRowAtIndexPath:(NSIndexPath *)path animated:(BOOL)animated {}
@end
@interface NSIndexPath (Table)
@property(readonly) NSInteger section, row;
@end
@implementation NSIndexPath (Table)
#ifndef GNUSTEP
- (NSInteger)section { return [self indexAtPosition:0]; }
#endif
- (NSInteger)row { return [self indexAtPosition:1]; }
@end
static NSIndexPath *row(NSInteger section, NSInteger item) {
    NSUInteger indexes[] = {section, item}; return [NSIndexPath indexPathWithIndexes:indexes length:2];
}
@interface PSSpecifier : NSObject
- (void)setProperty:(id)value forKey:(NSString *)key;
@end
@implementation PSSpecifier
- (void)setProperty:(id)value forKey:(NSString *)key {}
@end
@interface PSViewController : NSObject {
@protected NSArray *_specifiers;
}
@property(nonatomic, strong) UIView *view;
@property(nonatomic, copy) NSString *title;
- (void)viewDidLoad;
- (void)viewWillAppear:(BOOL)animated;
- (void)viewDidDisappear:(BOOL)animated;
- (NSArray *)loadSpecifiersFromPlistName:(NSString *)name target:(id)target;
- (PSSpecifier *)specifierForID:(NSString *)identifier;
@end
@implementation PSViewController
- (instancetype)init { if((self = [super init])) _view = [UIView new]; return self; }
- (void)viewDidLoad {}
- (void)viewWillAppear:(BOOL)animated {}
- (void)viewDidDisappear:(BOOL)animated {}
- (NSArray *)loadSpecifiersFromPlistName:(NSString *)name target:(id)target { return @[[PSSpecifier new]]; }
- (PSSpecifier *)specifierForID:(NSString *)identifier { return [_specifiers firstObject]; }
@end
static NSUInteger opens, sessions, requests, resumes, cancels, invalidations;
static NSURL *openedURL;
@interface UIApplication : NSObject
+ (instancetype)sharedApplication;
- (void)openURL:(NSURL *)url options:(NSDictionary *)options completionHandler:(id)completion;
- (void)openURL:(NSURL *)url;
@end
@implementation UIApplication
+ (instancetype)sharedApplication { return [self new]; }
- (void)openURL:(NSURL *)url { ++opens; openedURL = url; }
- (void)openURL:(NSURL *)url options:(NSDictionary *)options completionHandler:(id)completion { [self openURL:url]; }
@end
@interface TestConfiguration : NSObject
@property NSTimeInterval timeoutIntervalForRequest, timeoutIntervalForResource;
@property(nonatomic, strong) id URLCache, HTTPCookieStorage, URLCredentialStorage;
+ (instancetype)ephemeralSessionConfiguration;
@end
@implementation TestConfiguration
+ (instancetype)ephemeralSessionConfiguration { return [self new]; }
@end
@interface TestTask : NSObject
- (void)resume; - (void)cancel;
@end
@implementation TestTask
- (void)resume { ++resumes; }
- (void)cancel { ++cancels; }
@end
@interface TestSession : NSObject
@property(nonatomic, strong) id delegate;
@property(nonatomic, copy) void (^completion)(NSData *, NSURLResponse *, NSError *);
+ (instancetype)sessionWithConfiguration:(TestConfiguration *)configuration delegate:(id)delegate delegateQueue:(NSOperationQueue *)queue;
- (TestTask *)dataTaskWithURL:(NSURL *)url completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completion;
- (void)finishTasksAndInvalidate; - (void)invalidateAndCancel;
@end
static TestSession *lastSession;
@implementation TestSession
+ (instancetype)sessionWithConfiguration:(TestConfiguration *)configuration delegate:(id)delegate delegateQueue:(NSOperationQueue *)queue {
    ++sessions; assert(queue == [NSOperationQueue mainQueue]);
    assert(!configuration.URLCache && !configuration.HTTPCookieStorage && !configuration.URLCredentialStorage);
    lastSession = [self new]; lastSession.delegate = delegate; return lastSession;
}
- (TestTask *)dataTaskWithURL:(NSURL *)url completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completion {
    ++requests;
    assert([url.absoluteString isEqual:@"https://api.github.com/repos/jjolano/shadow/releases?per_page=10"]);
    self.completion = completion; return [TestTask new];
}
- (void)finishTasksAndInvalidate { ++invalidations; self.delegate = nil; }
- (void)invalidateAndCancel { ++invalidations; self.delegate = nil; }
@end
#define NSURLSession TestSession
#define NSURLSessionConfiguration TestConfiguration
#define NSURLSessionDataTask TestTask
#define NSURLSessionTask TestTask
static NSString *installedVersion;
static NSString *SHDWInstalledVersion(void) { return installedVersion; }
@interface SHDWAboutListController : PSViewController @end
'''
source += about[about.index('@implementation'):about.index('- (void)openGitHub:')] + '\n@end\n'
source += '@interface SHDWUpdatesController : PSViewController @end\n'
source += updates[updates.index('@implementation'):]
source += r'''
static void complete(NSData *data, NSInteger status, NSError *error) {
    void (^completion)(NSData *, NSURLResponse *, NSError *) = lastSession.completion;
    lastSession.completion = nil;
    completion(data, [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"https://api.github.com/repos/jjolano/shadow/releases"]
        statusCode:status HTTPVersion:@"HTTP/1.1" headerFields:nil], error);
}
static void completeJSON(id json) {
    complete([NSJSONSerialization dataWithJSONObject:json options:0 error:NULL], 200, nil);
}
static void exercisePane(SHDWUpdatesController *pane) {
    [pane viewWillAppear:NO];
    NSInteger sections = [pane numberOfSectionsInTableView:nil];
    for(NSInteger section = 0; section < sections; ++section) {
        [pane tableView:nil titleForHeaderInSection:section];
        [pane tableView:nil titleForFooterInSection:section];
        for(NSInteger item = 0; item < [pane tableView:nil numberOfRowsInSection:section]; ++item) {
            [pane tableView:nil heightForRowAtIndexPath:row(section, item)];
            [pane tableView:nil cellForRowAtIndexPath:row(section, item)];
        }
    }
}
'''
source += '''
// In-memory defaults double: no test keys can reach a user's persistent domain.
@interface TestDefaults : NSUserDefaults
@property(nonatomic, strong) NSMutableDictionary *storage;
@property(nonatomic) BOOL failSynchronize;
@end
@implementation TestDefaults
- (instancetype)init { if((self = [super init])) _storage = [NSMutableDictionary new]; return self; }
- (id)objectForKey:(NSString *)key { return _storage[key]; }
- (NSDictionary *)dictionaryForKey:(NSString *)key { return _storage[key]; }
- (NSDictionary *)dictionaryRepresentation { return [_storage copy]; }
- (void)setObject:(id)value forKey:(NSString *)key { _storage[key] = value; }
- (void)setBool:(BOOL)value forKey:(NSString *)key { _storage[key] = @(value); }
- (void)removeObjectForKey:(NSString *)key { [_storage removeObjectForKey:key]; }
- (BOOL)synchronize { return !self.failSynchronize; }
@end
static NSDictionary *parse(NSData *data, NSInteger status, NSError *error) {
    NSURLResponse *response = [[NSHTTPURLResponse alloc]
        initWithURL:[NSURL URLWithString:@"https://example.invalid/releases"]
        statusCode:status HTTPVersion:@"HTTP/1.1" headerFields:nil];
'''
source += parser
source += '''
    return @{@"version": version ?: @"", @"title": title ?: @"",
              @"body": body ?: @"", @"url": url.absoluteString ?: @"", @"failed": @(failed)};
}
static NSDictionary *parseJSON(id json) {
    return parse([NSJSONSerialization dataWithJSONObject:json options:0 error:NULL], 200, nil);
}
int main(void) { @autoreleasepool {
    Method existsMethod = class_getInstanceMethod([NSFileManager class], @selector(fileExistsAtPath:));
    Method contentsMethod = class_getClassMethod([NSString class], @selector(stringWithContentsOfFile:encoding:error:));
    IMP existsIMP = method_setImplementation(existsMethod, (IMP)testFileExists);
    IMP contentsIMP = method_setImplementation(contentsMethod, (IMP)testFileContents);
    localFiles = @{};
    assert(readInstalledVersion() == nil && fileReads == 0);
    for(NSString *status in @[@"Package: other\\nVersion: 9.0\\n",
        @"Package: me.jjolano.shadow\\nStatus: installed\\n\\nPackage: other\\nVersion: 9.0\\n",
        @"Package: me.jjolano.shadow\\nVersion:    \\n"]) {
        localFiles = @{@"/var/lib/dpkg/status": status};
        assert(readInstalledVersion() == nil);
    }
    localFiles = @{@"/test-bootstrap/var/lib/dpkg/status": @"Package: me.jjolano.shadow\\nVersion: 4.0.0-1\\n"};
    assert([readInstalledVersion() isEqual:@"4.0.0-1"]);
    NSUInteger reads = fileReads;
    assert([readInstalledVersion() isEqual:@"4.0.0-1"] && fileReads == reads);
    method_setImplementation(existsMethod, existsIMP);
    method_setImplementation(contentsMethod, contentsIMP);

    assert(![UIImage respondsToSelector:@selector(systemImageNamed:)]);
    assert(SHDWSettingsSymbol(@"info.circle") == nil);
    class_addMethod(object_getClass([UIImage class]), @selector(systemImageNamed:), (IMP)testSymbol, "@@:@");
    assert(SHDWSettingsSymbol(@"info.circle").renderingMode == UIImageRenderingModeAlwaysTemplate);
    assert(SHDWSettingsSymbol(@"missing") == nil);
    TestDefaults *prefs = [TestDefaults new];
    NSString *app = @"example.selected", *other = @"example.other";
    [prefs setBool:YES forKey:@"Global_Enabled"];
    [prefs setBool:NO forKey:SHDWDetectorAggressiveID];
    [prefs setObject:@{SHDWAppEnabledID: @NO} forKey:other];
    assert(SHDWAppFollowsGlobal(prefs, app));
    assert(!SHDWAppIsCustomized(@YES));
    assert(!SHDWAppIsCustomized(@{}));
    for(NSString *key in @[SHDWAppEnabledID, SHDWAppDisabledID, SHDWDetectorAggressiveID]) {
        for(NSNumber *value in @[@NO, @YES]) {
            NSDictionary *override = @{key: value, @"obsolete": @YES};
            [prefs setObject:override forKey:app];
            NSDictionary *before = [prefs dictionaryRepresentation];
            assert(!SHDWAppFollowsGlobal(prefs, app));
            assert(SHDWAppIsCustomized([prefs dictionaryForKey:app]));
            assert([[prefs dictionaryRepresentation] isEqual:before]);
            prefs.failSynchronize = YES;
            assert(!SHDWResetApp(prefs, app));
            NSMutableDictionary *expected = [before mutableCopy];
            [expected removeObjectForKey:app];
            // Failed persistence leaves current memory visible, without clobbering other keys.
            assert([[prefs dictionaryRepresentation] isEqual:expected]);
            prefs.failSynchronize = NO;
            assert(SHDWResetApp(prefs, app));
            [prefs setObject:override forKey:app];
            assert(SHDWResetApp(prefs, app));
            assert([[prefs dictionaryRepresentation] isEqual:expected]);
            assert([prefs objectForKey:app] == nil);
            assert(SHDWAppFollowsGlobal(prefs, app));
        }
    }
    NSDictionary *before = [prefs dictionaryRepresentation];
    assert(!SHDWResetApp(prefs, nil));
    assert(!SHDWResetApp(prefs, @""));
    assert(SHDWResetApp(prefs, app));
    assert([[prefs dictionaryRepresentation] isEqual:before]);

    NSString *longBody = [@"## Actual notes\\n- Fix with `code` and https://example.invalid\\n"
        stringByPaddingToLength:100000 withString:@"More release notes.\\n" startingAtIndex:0];
    NSDictionary *release = @{@"tag_name": @"v4.2.0", @"prerelease": @NO,
        @"name": @"Actual release title", @"body": longBody};
    NSDictionary *result = parseJSON(@[
        @{@"tag_name": @"artifacts", @"prerelease": @NO},
        @{@"tag_name": @"v5.0.0", @"prerelease": @YES},
        @{@"tag_name": @42, @"prerelease": @NO},
        @{@"tag_name": @"v8.0", @"prerelease": [NSNull null]},
        [NSNull null], release,
        @{@"tag_name": @"v4.1.0", @"prerelease": @NO}]);
    assert(![result[@"failed"] boolValue]);
    assert([result[@"version"] isEqual:@"4.2.0"]);
    assert([result[@"title"] isEqual:release[@"name"]]);
    assert([result[@"body"] isEqual:longBody]);
    result = parseJSON(@[@{@"tag_name": @"4.0", @"prerelease": @NO,
        @"name": [NSNull null], @"body": @42}]);
    assert([result[@"title"] isEqual:@"4.0"]);
    assert([result[@"body"] isEqual:@""]);
    assert(![parseJSON(@[])[@"failed"] boolValue]);
    assert([parseJSON(@{})[@"failed"] boolValue]);
    assert([parse([@"broken" dataUsingEncoding:NSUTF8StringEncoding], 200, nil)[@"failed"] boolValue]);
    assert([parse(nil, 200, nil)[@"failed"] boolValue]);
    assert([parse([NSData data], 403, nil)[@"failed"] boolValue]);
    assert([parse([NSData data], 200, [NSError errorWithDomain:@"network" code:1 userInfo:nil])[@"failed"] boolValue]);
    NSString *validURL = @"https://github.com/jjolano/shadow/releases/tag/v4.2.0";
    NSMutableDictionary *linked = [release mutableCopy];
    linked[@"html_url"] = validURL;
    assert([parseJSON(@[linked])[@"url"] isEqual:validURL]);
    for(id invalid in @[[NSNull null], @42, @"http://github.com/jjolano/shadow/releases/tag/v4.2.0",
        @"https://github.com.evil.test/jjolano/shadow/releases/tag/v4.2.0",
        @"https://github.com/other/shadow/releases/tag/v4.2.0",
        @"https://github.com/jjolano/other/releases/tag/v4.2.0",
        @"https://user@github.com/jjolano/shadow/releases/tag/v4.2.0",
        @"https://github.com:443/jjolano/shadow/releases/tag/v4.2.0",
        @"https://github.com/jjolano/shadow/releases/tag/v4.2.0?next=evil",
        @"https://github.com/jjolano/shadow/releases/tag/v4.2.0#fragment",
        @"https://github.com/jjolano/shadow/releases/tag/other",
        @"https://github.com/jjolano/shadow/releases/tag/v4.2.0/../../other",
        @"https://github.com/jjolano/shadow/releases/tag/v4.2.0%2f..", @"%"] ) {
        linked[@"html_url"] = invalid;
        assert([parseJSON(@[linked])[@"url"] length] == 0);
    }
    linked[@"html_url"] = validURL;
    SHDWAboutListController *about = [SHDWAboutListController new];
    [about viewDidLoad]; [about viewWillAppear:NO];
    for(int i = 0; i < 2; ++i) {
        [about specifiers]; [about aboutDeveloper:nil]; [about aboutTranslator:nil];
        assert([[about aboutInstalledVersion:nil] isEqual:@"UNKNOWN"]);
    }
    SHDWUpdatesController *pane = [SHDWUpdatesController new];
    assert(sessions == 0 && requests == 0 && resumes == 0 && opens == 0);
    [pane viewDidLoad]; exercisePane(pane); exercisePane(pane);
    assert([pane numberOfSectionsInTableView:nil] == 1);
    assert([[pane tableView:nil cellForRowAtIndexPath:row(0, 0)].detailTextLabel.text isEqual:@"UNKNOWN"]);
    assert(sessions == 0 && requests == 0 && resumes == 0 && opens == 0);

    [pane tableView:nil didSelectRowAtIndexPath:row(0, 1)];
    [pane tableView:nil didSelectRowAtIndexPath:row(0, 1)];
    [pane checkForUpdates:nil]; exercisePane(pane);
    assert(sessions == 1 && requests == 1 && resumes == 1 && opens == 0);
    assert(![pane tableView:nil cellForRowAtIndexPath:row(0, 1)].userInteractionEnabled);
    __block BOOL redirectRefused = NO;
    [pane URLSession:lastSession task:nil willPerformHTTPRedirection:nil newRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:@"https://example.invalid"]]
        completionHandler:^(NSURLRequest *request) { redirectRefused = (request == nil); }];
    assert(redirectRefused);
    completeJSON(@[linked]); exercisePane(pane);
    assert(requests == 1 && [pane numberOfSectionsInTableView:nil] == 3 && opens == 0);
    assert([[pane updateStatus] isEqual:@"UNKNOWN"]);
    installedVersion = @"4.1.0";
    assert([[about aboutInstalledVersion:nil] isEqual:installedVersion]);
    assert([[pane updateStatus] isEqual:@"UPDATE_AVAILABLE"]);
    installedVersion = @"4.2.0-1";
    assert([[pane updateStatus] isEqual:@"UP_TO_DATE"]);
    assert([[pane tableView:nil cellForRowAtIndexPath:row(0, 1)].textLabel.text isEqual:@"CHECK_AGAIN"]);
    assert([pane tableView:nil cellForRowAtIndexPath:row(1, 2)].detailTextLabel.text.length > 0);
    UITextView *notes = [[pane tableView:nil cellForRowAtIndexPath:row(2, 0)].contentView.subviews firstObject];
    assert(!notes.editable && notes.selectable && notes.scrollEnabled && notes.dataDetectorTypes == UIDataDetectorTypeNone);
    assert([notes.text containsString:longBody]);
    [pane tableView:nil didSelectRowAtIndexPath:row(2, 1)];
    assert(opens == 1 && [openedURL.absoluteString isEqual:validURL]);

    [pane tableView:nil didSelectRowAtIndexPath:row(0, 1)];
    assert(requests == 2 && resumes == 2 && [pane numberOfSectionsInTableView:nil] == 1);
    [pane tableView:nil didSelectRowAtIndexPath:row(2, 1)]; assert(opens == 1);
    complete(nil, 503, nil); exercisePane(pane);
    assert([pane numberOfSectionsInTableView:nil] == 2);
    assert([[pane updateStatus] isEqual:@"NOTES_ERROR"]);
    assert([[pane tableView:nil cellForRowAtIndexPath:row(0, 1)].textLabel.text isEqual:@"NOTES_RETRY"]);
    assert([[pane tableView:nil cellForRowAtIndexPath:row(1, 0)].detailTextLabel.text isEqual:@"UNKNOWN"]);
    [pane tableView:nil didSelectRowAtIndexPath:row(2, 1)]; assert(opens == 1);
    [pane tableView:nil didSelectRowAtIndexPath:row(0, 1)];
    assert(requests == 3); completeJSON(@[]); exercisePane(pane);
    assert([[pane updateStatus] isEqual:@"NOTES_NO_RELEASE"]);
    assert([pane numberOfSectionsInTableView:nil] == 2);
    [pane checkForUpdates:nil]; completeJSON(@[@{@"tag_name": @"v4.0", @"prerelease": @NO, @"body": @"  "}]);
    notes = [[pane tableView:nil cellForRowAtIndexPath:row(2, 0)].contentView.subviews firstObject];
    assert([notes.text containsString:@"NOTES_EMPTY"]);
    assert([pane tableView:nil numberOfRowsInSection:2] == 1);
    [pane tableView:nil didSelectRowAtIndexPath:row(2, 1)]; assert(opens == 1);

    [pane checkForUpdates:nil]; assert(requests == 5);
    void (^lateCompletion)(NSData *, NSURLResponse *, NSError *) = lastSession.completion;
    [pane viewDidDisappear:NO];
    assert(cancels == 1 && invalidations == 5 && lastSession.delegate == nil);
    exercisePane(pane); assert(requests == 5);
    [pane checkForUpdates:nil]; assert(requests == 6);
    lateCompletion(nil, nil, nil);
    assert([pane numberOfSectionsInTableView:nil] == 1);
    [pane checkForUpdates:nil]; assert(requests == 6);
    completeJSON(@[linked]);
    assert([pane numberOfSectionsInTableView:nil] == 3);
    // Every failed retry must remove the prior valid release and its action.
    for(NSNumber *status in @[@302, @403, @429, @500, @200, @204]) {
        [pane checkForUpdates:nil];
        complete([@"broken" dataUsingEncoding:NSUTF8StringEncoding], status.integerValue, nil);
        assert([[pane updateStatus] isEqual:@"NOTES_ERROR"]);
        assert([pane numberOfSectionsInTableView:nil] == 2);
        [pane tableView:nil didSelectRowAtIndexPath:row(2, 1)]; assert(opens == 1);
        [pane checkForUpdates:nil]; completeJSON(@[linked]);
    }
    [pane checkForUpdates:nil];
    complete(nil, 200, [NSError errorWithDomain:@"network" code:1 userInfo:nil]);
    assert([[pane updateStatus] isEqual:@"NOTES_ERROR"]);
    [pane tableView:nil didSelectRowAtIndexPath:row(2, 1)]; assert(opens == 1);
    [pane viewDidDisappear:NO];
    __weak id weakPane = pane;
    pane = nil; lastSession = nil;
    assert(weakPane == nil);
    puts("PASS: actual settings helpers, parser, About getters, Updates lifecycle/actions, cancellation, inline notes and URL validation (host doubles, no device)");
} return 0; }
'''

args = argparse.ArgumentParser(description=__doc__)
args.add_argument("--docker", metavar="IMAGE")
options = args.parse_args()
with tempfile.TemporaryDirectory(prefix="shadow-settings-") as directory:
    temporary = Path(directory)
    (temporary / "test.m").write_text(source)
    if options.docker:
        subprocess.run([
            "docker", "run", "--rm", "--network=none", "-v", f"{temporary}:/test",
            "-w", "/test", options.docker, "sh", "-ec",
            "clang -fblocks -fobjc-arc -fobjc-runtime=gnustep-2.0 $(gnustep-config --objc-flags) "
            "-UNDEBUG test.m -o test $(gnustep-config --base-libs) && ./test",
        ], check=True)
    else:
        flags = ["-framework", "Foundation"] if platform.system() == "Darwin" else (
            ["-fobjc-runtime=gnustep-2.0"] + shlex.split(subprocess.check_output(
                ["gnustep-config", "--objc-flags"], text=True)) + shlex.split(
                subprocess.check_output(["gnustep-config", "--base-libs"], text=True)))
        subprocess.run(["clang", "-fblocks", "-fobjc-arc", *flags, "-UNDEBUG", "test.m", "-o", "test"],
                       cwd=temporary, check=True)
        subprocess.run([str(temporary / "test")], check=True)
