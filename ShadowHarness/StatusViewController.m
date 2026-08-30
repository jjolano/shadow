#import "StatusViewController.h"

#import <Shadow.h>
#import <Shadow/JBPath.h>
#import <Shadow/Settings.h>

#import <mach-o/dyld.h>
#import <objc/runtime.h>

#import "Battery.h"

// Private libdyld symbol (declared in dyld_priv.h in ShadowCore, extern here
// for the IMP-image diagnosis below).
extern const char* dyld_image_path_containing_address(const void* addr);

// UICellAccessorySwitch is a real public API since iOS 14 but is not declared
// in this SDK's UICellAccessory.h — declare it locally (same pattern as the
// _NSGetArgv extern below).
@interface UICellAccessorySwitch : UICellAccessory
@property (nonatomic, getter=isOn) BOOL on;
@property (nonatomic, copy) void (^handler)(void);
- (instancetype)initWithIsOn:(BOOL)on handler:(void (^)(void))handler;
@end

// Shadow's own prefs plist (mirrors common.h SHADOW_PREFS_PLIST; kept local
// so the harness does not depend on the framework source tree).
static NSString* const kShadowPrefsPlist = @"/var/mobile/Library/Preferences/me.jjolano.shadow.plist";

// Same argv[0] probe the stub's ctor evaluates (Shadow.dylib/dylib.x) —
// shown in the why rows so a user can see the path Shadow's loader saw.
extern char*** _NSGetArgv();

#pragma mark - Typed model

typedef NS_ENUM(NSInteger, ShdwRowKind) {
	ShdwRowKindDefault,
	ShdwRowKindSwitch,
};

// One list row. Instances double as diffable-data-source item identifiers
// (identity hashing; every rebuild produces fresh objects, so no duplicates
// within a snapshot).
@interface ShdwRow : NSObject
@property (nonatomic, copy) NSString* text;
@property (nonatomic, copy) NSString* detail;
@property (nonatomic) ShdwRowKind kind;
@property (nonatomic) BOOL on;
@property (nonatomic, copy) NSString* symbolName;   // SF Symbol, nil = none
@property (nonatomic, strong) UIColor* symbolTint;
@end

@implementation ShdwRow
@end

// One list section. Also the section identifier.
@interface ShdwSection : NSObject
@property (nonatomic, copy) NSString* title;
@property (nonatomic, copy) NSArray<ShdwRow*>* rows;
@end

@implementation ShdwSection
@end

static ShdwRow* shdw_row(NSString* text, NSString* detail) {
	ShdwRow* row = [ShdwRow new];
	row.text = text;
	row.detail = detail;
	return row;
}

static ShdwSection* shdw_section(NSString* title, NSArray<ShdwRow*>* rows) {
	ShdwSection* section = [ShdwSection new];
	section.title = title;
	section.rows = rows;
	return section;
}

// Symbol semantics, one place so both probe sections agree:
// green checkmark = works/hidden/PASS, orange triangle = gap/visible,
// gray info = informational, yellow questionmark = MIXED.
static void shdw_style_row_for_verdict(ShdwRow* row, NSString* verdict) {
	if([verdict isEqualToString:@"hidden"] || [verdict isEqualToString:@"PASS"]) {
		row.symbolName = @"checkmark.circle.fill";
		row.symbolTint = [UIColor systemGreenColor];
	} else if([verdict isEqualToString:@"visible"] ||
			  [verdict isEqualToString:@"GAP"] || [verdict isEqualToString:@"HOOK-GAP"]) {
		row.symbolName = @"exclamationmark.triangle.fill";
		row.symbolTint = [UIColor systemOrangeColor];
	} else if([verdict isEqualToString:@"MIXED"]) {
		row.symbolName = @"questionmark.circle";
		row.symbolTint = [UIColor systemYellowColor];
	} else { // n/a, INFO
		row.symbolName = @"info.circle";
		row.symbolTint = [UIColor systemGrayColor];
	}
}

// ShadowSettings class only exists when Shadow.framework is loaded. The
// harness links the framework, so it is present at runtime; fall back to a
// raw NSUserDefaults suite read for the not-loaded case.
static NSUserDefaults* shdw_prefs(void) {
	return [[NSUserDefaults alloc] initWithSuiteName:kShadowPrefsPlist];
}

static NSDictionary* shdw_shadow_settings_for(NSString* bundleID) {
	Class settingsClass = ShdwShadowClass("ShadowSettings");
	if(settingsClass && [settingsClass respondsToSelector:@selector(sharedInstance)]) {
		id settings = [settingsClass sharedInstance];
		if(settings && [settings respondsToSelector:@selector(getPreferencesForIdentifier:)]) {
			NSDictionary* prefs = [settings getPreferencesForIdentifier:bundleID];
			if(prefs) {
				return prefs;
			}
		}
	}
	return nil;
}

// Rule counts are cached per ruleset path + mtime so unchanged rulesets are
// not re-read (disk read + plist parse + compile) on every refresh; see
// rulesetSection. Dev mode does not change ruleset semantics, so the toggle
// leaves the cache alone.

@interface StatusViewController () <UICollectionViewDelegate>
@end

@implementation StatusViewController {
	UICollectionView* _collectionView;
	UICollectionViewDiffableDataSource<ShdwSection*, ShdwRow*>* _dataSource;
	NSArray<ShdwSection*>* _sections;
	BOOL _devMode;
}

static NSString* const kCellReuseID = @"Cell";
static NSString* const kHeaderReuseID = @"Header";

- (void)viewDidLoad {
	[super viewDidLoad];

	self.title = @"Shadow Harness";
	self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeAlways;
	self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
		initWithTitle:@"Copy diagnostics" style:UIBarButtonItemStylePlain
		target:self action:@selector(copyDiagnostics:)];

	UICollectionLayoutListConfiguration* listConfig =
		[[UICollectionLayoutListConfiguration alloc] initWithAppearance:UICollectionLayoutListAppearanceInsetGrouped];
	listConfig.headerMode = UICollectionLayoutListHeaderModeSupplementary;
	// +layoutWithListConfiguration: is missing from this SDK's headers; the
	// section-provider initializer covers the same single-section-type list.
	UICollectionViewCompositionalLayout* layout =
		[[UICollectionViewCompositionalLayout alloc] initWithSectionProvider:
			^NSCollectionLayoutSection*(NSInteger sectionIndex, id<NSCollectionLayoutEnvironment> environment) {
				return [NSCollectionLayoutSection sectionWithListConfiguration:listConfig layoutEnvironment:environment];
			}];

	_collectionView = [[UICollectionView alloc] initWithFrame:self.view.bounds collectionViewLayout:layout];
	_collectionView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
	_collectionView.delegate = self;
	[self.view addSubview:_collectionView];

	[_collectionView registerClass:[UICollectionViewListCell class] forCellWithReuseIdentifier:kCellReuseID];
	[_collectionView registerClass:[UICollectionViewListCell class]
		forSupplementaryViewOfKind:UICollectionElementKindSectionHeader withReuseIdentifier:kHeaderReuseID];

	__weak __typeof(self) weakSelf = self;
	_dataSource = [[UICollectionViewDiffableDataSource alloc] initWithCollectionView:_collectionView
		cellProvider:^UICollectionViewCell*(UICollectionView* collectionView, NSIndexPath* indexPath, ShdwRow* row) {
			return [weakSelf collectionView:collectionView cellForRow:row atIndexPath:indexPath];
		}];
	_dataSource.supplementaryViewProvider =
		^UICollectionReusableView*(UICollectionView* collectionView, NSString* elementKind, NSIndexPath* indexPath) {
			return [weakSelf collectionView:collectionView headerAtIndexPath:indexPath];
		};

	_devMode = NO;
	_sections = [self buildSectionsIncludingBattery:NO];
	[self applySnapshotAnimated:NO];
}

- (void)viewWillAppear:(BOOL)animated {
	[super viewWillAppear:animated];
	// Re-run the probes every time the view appears — cheap, and the
	// diagnostics stay fresh.
	_sections = [self buildSectionsIncludingBattery:NO];
	[self applySnapshotAnimated:NO];
	// Automation hook: full diagnostics (incl. battery) to a file in the
	// app container, readable over SSH for autonomous result capture.
	[StatusViewController writeStealthReport];

	// ShadowCore's install is deferred out of the dyld initializer context
	// (see shadowcore.x shdw_coordinator_ctor) and completes on a background
	// queue shortly after launch. The first viewWillAppear can run before the
	// install finishes, so the "Shadow active" row would show a stale NO.
	// Re-run the probes once the install has had time to complete.
	__weak __typeof(self) weakSelf = self;
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
		__strong __typeof(weakSelf) strongSelf = weakSelf;
		if(!strongSelf) {
			return;
		}
		strongSelf->_sections = [strongSelf buildSectionsIncludingBattery:NO];
		[strongSelf applySnapshotAnimated:NO];
		[StatusViewController writeStealthReport];
	});
}

#pragma mark - Cells

- (UICollectionViewCell*)collectionView:(UICollectionView*)collectionView cellForRow:(ShdwRow*)row atIndexPath:(NSIndexPath*)indexPath {
	UICollectionViewListCell* cell = [collectionView dequeueReusableCellWithReuseIdentifier:kCellReuseID forIndexPath:indexPath];

	UIListContentConfiguration* config = [UIListContentConfiguration subtitleCellConfiguration];
	config.text = row.text;
	config.secondaryText = row.detail;
	// Long diagnostic strings must wrap.
	config.secondaryTextProperties.numberOfLines = 0;
	if(row.symbolName) {
		config.image = [UIImage systemImageNamed:row.symbolName];
		config.imageProperties.tintColor = row.symbolTint;
	}
	cell.contentConfiguration = config;

	if(row.kind == ShdwRowKindSwitch) {
		__weak __typeof(self) weakSelf = self;
		// NSClassFromString, not a direct class ref: this SDK's UIKit.tbd
		// doesn't export UICellAccessorySwitch for arm64e, so a class ref
		// fails at link time. The class exists at runtime on iOS 14+.
		Class switchClass = NSClassFromString(@"UICellAccessorySwitch");

		// UICellAccessorySwitch is iOS 16+; on older systems the class is
		// nil, and @[ [[nil alloc] init...] ] raises an NSArray
		// nil-element exception in cellForItemAtIndexPath. Guard the
		// accessory, and on iOS 14/15 fall back to a plain UISwitch wrapped
		// in a custom-view accessory (iOS 14+) so dev mode stays reachable.
		if(switchClass) {
			cell.accessories = @[ [[switchClass alloc] initWithIsOn:row.on handler:^{
				[weakSelf devModeToggled];
			}] ];
		} else {
			UISwitch* toggle = [UISwitch new];
			toggle.on = row.on;
			[toggle addTarget:self action:@selector(devModeToggled) forControlEvents:UIControlEventValueChanged];
			cell.accessories = @[ [[UICellAccessoryCustomView alloc] initWithCustomView:toggle placement:UICellAccessoryPlacementTrailing] ];
		}
	} else {
		cell.accessories = @[];
	}

	return cell;
}

- (UICollectionReusableView*)collectionView:(UICollectionView*)collectionView headerAtIndexPath:(NSIndexPath*)indexPath {
	UICollectionViewListCell* header = [collectionView
		dequeueReusableSupplementaryViewOfKind:UICollectionElementKindSectionHeader
		withReuseIdentifier:kHeaderReuseID forIndexPath:indexPath];
	UIListContentConfiguration* config = header.defaultContentConfiguration;
	config.text = [_sections[indexPath.section] title];
	header.contentConfiguration = config;
	return header;
}

- (void)applySnapshotAnimated:(BOOL)animated {
	NSDiffableDataSourceSnapshot<ShdwSection*, ShdwRow*>* snapshot = [NSDiffableDataSourceSnapshot new];
	[snapshot appendSectionsWithIdentifiers:_sections];
	for(ShdwSection* section in _sections) {
		[snapshot appendItemsWithIdentifiers:section.rows intoSectionWithIdentifier:section];
	}
	[_dataSource applySnapshot:snapshot animatingDifferences:animated];
}

#pragma mark - Model

- (NSArray<ShdwSection*>*)buildSectionsIncludingBattery:(BOOL)includeBattery {
	NSMutableArray* sections = [NSMutableArray new];

	[sections addObject:[self shadowStatusSection]];
	[sections addObject:[self thisAppSection]];
	[sections addObject:[self rulesetSection]];
	[sections addObject:[self canonicalSection]];
	[sections addObject:[self devModeSection]];

	if(_devMode || includeBattery) {
		[sections addObject:[self batterySection]];
	}

	return sections;
}

- (ShdwSection*)shadowStatusSection {
	NSMutableArray* rows = [NSMutableArray new];

	// The harness links Shadow.framework directly, so class presence says
	// nothing about whether Shadow is actually filtering this process. The
	// hooks payload (ShadowCore.dylib) is the primary answer.
	BOOL payloadActive = ShdwIsShadowCoreLoaded();
	BOOL classHidingActive = ShdwIsShadowClassHidingActive();
	BOOL enginePresent = ShdwShadowClass("Shadow") != nil;

	if(payloadActive) {
		Shadow* shadow = [ShdwShadowClass("Shadow") sharedInstance];

		ShdwRow* activeRow = shdw_row(@"Shadow active (hooks payload)", @"YES");
		activeRow.symbolName = @"checkmark.circle.fill";
		activeRow.symbolTint = [UIColor systemGreenColor];
		[rows addObject:activeRow];

		[rows addObject:shdw_row(@"Engine present (framework)", @"YES")];
		ShdwRow* classHidingRow = shdw_row(@"Class hiding", classHidingActive ? @"YES" : @"NO");
		classHidingRow.symbolName = classHidingActive ? @"checkmark.circle.fill" : @"exclamationmark.triangle.fill";
		classHidingRow.symbolTint = classHidingActive ? [UIColor systemGreenColor] : [UIColor systemOrangeColor];
		[rows addObject:classHidingRow];
		[rows addObject:shdw_row(@"Rootless", shadow.rootless ? @"yes" : @"no")];
		[rows addObject:shdw_row(@"Has app sandbox", shadow.hasAppSandbox ? @"yes" : @"no")];
		[rows addObject:shdw_row(@"Bundle path", shadow.bundlePath)];
		[rows addObject:shdw_row(@"Home path", shadow.homePath)];
	} else {
		ShdwRow* activeRow = shdw_row(@"Shadow active (hooks payload)", @"NO");
		activeRow.symbolName = @"xmark.circle";
		activeRow.symbolTint = [UIColor systemRedColor];
		[rows addObject:activeRow];

		[rows addObject:shdw_row(@"Engine present (framework)", enginePresent ? @"YES" : @"NO")];

		// "Why" rows: the path the stub's gate evaluated, then this app's
		// own entry in Shadow's prefs. The keys are App_Enabled (per-app
		// override) and Global_Enabled (always-on); with neither set, the
		// stub skips this app by design.
		[rows addObject:shdw_row(@"Executable path", @(**_NSGetArgv()))];

		NSString* bundleID = [NSBundle mainBundle].bundleIdentifier;
		NSUserDefaults* prefs = shdw_prefs();
		NSDictionary* appSettings = bundleID ? [prefs objectForKey:bundleID] : nil;
		NSNumber* appDisabled = appSettings ? appSettings[@"App_Disabled"] : nil;
		NSNumber* appEnabled = appSettings ? appSettings[@"App_Enabled"] : nil;
		NSNumber* globalEnabled = [prefs objectForKey:@"Global_Enabled"];

		if(appSettings) {
			[rows addObject:shdw_row(@"Per-app override",
				[NSString stringWithFormat:@"present (App_Enabled=%@, App_Disabled=%@)", appEnabled ? appEnabled : @"(unset)", appDisabled ? appDisabled : @"(unset)"])];
		} else {
			[rows addObject:shdw_row(@"Per-app override", @"absent")];
		}
		[rows addObject:shdw_row(@"Global_Enabled", globalEnabled ? [globalEnabled boolValue] ? @"YES" : @"NO" : @"(unreadable)")];

		if([appDisabled boolValue]) {
			[rows addObject:shdw_row(@"Filter disabled", @"App_Disabled=YES — Shadow skips this app")];
		} else if([appEnabled boolValue]) {
			[rows addObject:shdw_row(@"Filter enabled", @"App_Enabled=YES — Shadow should be active")];
		} else if([globalEnabled boolValue]) {
			[rows addObject:shdw_row(@"Filter enabled", @"Global_Enabled=YES — Shadow should be active")];
		} else {
			[rows addObject:shdw_row(@"Filter disabled",
				@"App_Enabled and Global_Enabled both off — Shadow skips this app")];
		}
		[rows addObject:shdw_row(@"Hint", @"Check Shadow settings for this app")];
	}

	return shdw_section(@"Shadow status", rows);
}

- (ShdwSection*)thisAppSection {
	NSString* bundleID = [NSBundle mainBundle].bundleIdentifier;
	NSUserDefaults* prefs = shdw_prefs();
	NSDictionary* appSettings = bundleID ? [prefs objectForKey:bundleID] : nil;
	BOOL appDisabled = [appSettings[@"App_Disabled"] boolValue];
	NSNumber* globalEnabled = [prefs objectForKey:@"Global_Enabled"];

	// App_Disabled overrides the per-app and global enable paths.
	BOOL appEnabled = [appSettings[@"App_Enabled"] boolValue];
	BOOL filtered = !appDisabled && (appEnabled || [globalEnabled boolValue]);

	// Prefer ShadowSettings' merged view (defaults + per-app inheritance);
	// fall back to the raw suite when the class is unavailable.
	NSDictionary* merged = shdw_shadow_settings_for(bundleID);
	if(merged && !appDisabled) {
		filtered = [merged[@"App_Enabled"] boolValue];
	}

	NSString* modeDetail = appDisabled ? @"App_Disabled=YES" : appEnabled ? @"App_Enabled=YES (per-app)" :
		[globalEnabled boolValue] ? @"Global_Enabled=YES" : @"neither key set";

	return shdw_section(@"This app", @[
		shdw_row(@"Bundle ID", bundleID ? bundleID : @"(nil)"),
		shdw_row(@"Filter mode", filtered ? [@"filtered — " stringByAppendingString:modeDetail] : [@"off — " stringByAppendingString:modeDetail]),
		shdw_row(@"Per-app override present?", appSettings ? @"yes" : @"no"),
	]);
}

- (ShdwSection*)rulesetSection {
	NSMutableArray* rows = [NSMutableArray new];

	if(!ShdwShadowClass("Shadow")) {
		[rows addObject:shdw_row(@"n/a", @"Shadow not loaded")];
		return shdw_section(@"Ruleset", rows);
	}

	NSString* rulesetsDir = JBPath(@"/Library/Shadow/Rulesets");
	NSArray<NSString*>* files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:rulesetsDir error:nil];
	files = [files sortedArrayUsingSelector:@selector(localizedStandardCompare:)];

	NSDateFormatter* dateFormatter = [NSDateFormatter new];
	dateFormatter.dateStyle = NSDateFormatterMediumStyle;
	dateFormatter.timeStyle = NSDateFormatterShortStyle;

	for(NSString* file in files) {
		// Compiled caches next to ruleset plists are not rulesets.
		if([file hasSuffix:@"shadowcache"]) {
			continue;
		}

		NSString* fullPath = [rulesetsDir stringByAppendingPathComponent:file];
		NSDictionary* attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:fullPath error:nil];
		NSString* mtime = attrs[NSFileModificationDate] ? [dateFormatter stringFromDate:attrs[NSFileModificationDate]] : @"?";

		NSUInteger ruleCount = [[NSDictionary dictionaryWithContentsOfFile:fullPath] count];

		[rows addObject:shdw_row(file, [NSString stringWithFormat:@"%@ — %lu rules", mtime, (unsigned long)ruleCount])];
	}

	if(!rows.count) {
		[rows addObject:shdw_row(@"No rulesets", rulesetsDir)];
	}

	return shdw_section(@"Ruleset", rows);
}

- (ShdwSection*)canonicalSection {
	NSMutableArray* rows = [NSMutableArray new];
	for(NSDictionary* probe in ShdwCanonicalProbes()) {
		ShdwRow* row = shdw_row(probe[@"probe"],
			[NSString stringWithFormat:@"engine: %@", probe[@"verdict"]]);
		shdw_style_row_for_verdict(row, probe[@"verdict"]);
		[rows addObject:row];
	}
	return shdw_section(@"Canonical probes", rows);
}

- (ShdwSection*)devModeSection {
	NSMutableArray* rows = [NSMutableArray new];

	ShdwRow* toggle = shdw_row(@"Dev mode", nil);
	toggle.kind = ShdwRowKindSwitch;
	toggle.on = _devMode;
	[rows addObject:toggle];

	if(_devMode) {
		ShdwRow* footnote = shdw_row(@"Footnote", @"known/public techniques only — not proof of undetectability.");
		footnote.symbolName = @"info.circle";
		footnote.symbolTint = [UIColor systemGrayColor];
		[rows addObject:footnote];
	}
	return shdw_section(@"Dev mode", rows);
}

- (ShdwSection*)batterySection {
	NSArray<NSDictionary*>* batteryRows = ShdwBatteryRows();

	NSUInteger fired = 0;
	for(NSDictionary* batteryRow in batteryRows) {
		if([batteryRow[@"fired"] boolValue]) {
			fired++;
		}
	}

	NSMutableArray* rows = [NSMutableArray new];
	ShdwRow* summary = shdw_row(@"Detector fired",
		[NSString stringWithFormat:@"%lu/%lu probes fired", (unsigned long)fired, (unsigned long)batteryRows.count]);
	summary.symbolName = @"info.circle";
	summary.symbolTint = [UIColor systemGrayColor];
	[rows addObject:summary];

	for(NSDictionary* batteryRow in batteryRows) {
		ShdwRow* row = shdw_row(batteryRow[@"name"],
			[NSString stringWithFormat:@"%@ — raw %@ / libc %@ / engine %@ — reason: %@",
				batteryRow[@"verdict"], batteryRow[@"raw"], batteryRow[@"filtered"],
				batteryRow[@"engine"], batteryRow[@"reason"]]);
		shdw_style_row_for_verdict(row, batteryRow[@"verdict"]);
		[rows addObject:row];
	}

	return shdw_section(@"Detector battery", rows);
}

#pragma mark - Selection

- (BOOL)collectionView:(UICollectionView*)collectionView shouldSelectItemAtIndexPath:(NSIndexPath*)indexPath {
	ShdwRow* row = _sections[indexPath.section].rows[indexPath.item];
	return row.kind == ShdwRowKindDefault;
}

- (void)collectionView:(UICollectionView*)collectionView didSelectItemAtIndexPath:(NSIndexPath*)indexPath {
	[collectionView deselectItemAtIndexPath:indexPath animated:YES];
}

#pragma mark - Actions

- (void)devModeToggled {
	_devMode = !_devMode;
	_sections = [self buildSectionsIncludingBattery:NO];
	[self applySnapshotAnimated:YES];
}

- (NSString *)diagnosticsString {
	NSMutableArray* fullSections = [[self buildSectionsIncludingBattery:YES] mutableCopy];

	// Ground truth for autonomous engine diagnostics: what's actually loaded
	// in this process and whether the engine answers.
	[fullSections addObject:[self engineDebugSection]];

	// ShdwDiagnosticsDump consumes the legacy dict shape {title, rows:[{text,
	// detail}]}; adapt the typed model back into it. The switch row carries
	// no detail, matching the old dump output.
	NSMutableArray* dicts = [NSMutableArray new];
	for(ShdwSection* section in fullSections) {
		NSMutableArray* rows = [NSMutableArray new];
		for(ShdwRow* row in section.rows) {
			[rows addObject:row.detail.length ?
				@{ @"text" : row.text, @"detail" : row.detail } :
				@{ @"text" : row.text }];
		}
		[dicts addObject:@{ @"title" : section.title, @"rows" : rows }];
	}

	return ShdwDiagnosticsDump(dicts);
}

- (ShdwSection*)engineDebugSection {
	NSMutableArray* rows = [NSMutableArray new];

	Class shadowClass = ShdwShadowClass("Shadow");
	[rows addObject:shdw_row(@"Shadow class (internal path)", shadowClass ? @"present" : @"nil")];

	Shadow* instance = shadowClass ? [shadowClass sharedInstance] : nil;
	[rows addObject:shdw_row(@"sharedInstance", instance ? @"non-nil" : @"nil")];
	if(instance) {
		[rows addObject:shdw_row(@"rootless", instance.rootless ? @"yes" : @"no")];
		[rows addObject:shdw_row(@"hasAppSandbox", instance.hasAppSandbox ? @"yes" : @"no")];
		[rows addObject:shdw_row(@"bundlePath", instance.bundlePath)];
		[rows addObject:shdw_row(@"homePath", instance.homePath)];
		[rows addObject:shdw_row(@"isPathRestricted(/var/jb)", [instance isPathRestricted:@"/var/jb"] ? @"YES" : @"NO")];
	}

	NSInteger count = 0;
	for(uint32_t i = 0; i < _dyld_image_count(); i++) {
		const char* name = _dyld_get_image_name(i);
		if(name && strstr(name, "Shadow")) {
			[rows addObject:shdw_row([NSString stringWithFormat:@"image %u", (unsigned)i], @(name))];
			count++;
		}
	}
	if(!count) {
		[rows addObject:shdw_row(@"dyld images", @"none match Shadow")];
	}

	// Scheme-hook diagnosis: if the UIApplication group installed,
	// canOpenURL:'s IMP points inside ShadowCore.dylib. Otherwise it is the
	// stock UIKit implementation (from the dyld shared cache) and the group
	// never installed — an install-path bug, not a filtering bug.
	NSString* uiImp = nil;
	SEL sel = NSSelectorFromString(@"canOpenURL:");
	Method m = class_getInstanceMethod([UIApplication class], sel);
	if(m) {
		const void* imp = method_getImplementation(m);
		const char* impImage = dyld_image_path_containing_address(imp);
		uiImp = impImage ? @(impImage) : @"(unresolved)";
	} else {
		uiImp = @"(no such method)";
	}
	[rows addObject:shdw_row(@"UIApplication canOpenURL: IMP image", uiImp)];

	// UIKit image names as dyld sees them: the watcher matches
	// "uikit.framework" in the image path — on iOS 12+ the real binary is
	// UIKitCore, and a stub-only image list would never match the check.
	uint32_t uiCount = 0;
	for(uint32_t i = 0; i < _dyld_image_count() && uiCount < 4; i++) {
		const char* name = _dyld_get_image_name(i);
		if(name && strstr(name, "UIKit")) {
			[rows addObject:shdw_row([NSString stringWithFormat:@"UIKit image %u", (unsigned)i], @(name))];
			uiCount++;
		}
	}
	if(!uiCount) {
		[rows addObject:shdw_row(@"UIKit images", @"none found")];
	}

	return shdw_section(@"Engine debug", rows);
}

// Nonce-bound machine report to the app container, for SSH capture.
+ (BOOL)writeStealthReport {
	NSString* dir = ShdwDocumentsDirectory();
	NSString* contextPath = dir ?
		[dir stringByAppendingPathComponent:@".ShadowStealthContext.json"] : nil;
	NSData* contextData = contextPath ? ShdwReadEvidenceData(contextPath) : nil;
	NSDictionary* context = contextData ?
		[NSJSONSerialization JSONObjectWithData:contextData options:0 error:nil] : nil;
	NSDictionary* report = ShdwStealthReport();
	if(!report && [context isKindOfClass:[NSDictionary class]]) {
		NSString* mode = context[@"requested_mode"];
		NSString* canary = [mode isEqualToString:@"uninjected"] ? @"CONTROL-INACTIVE" : @"FAIL";
		report = @{
			@"schema_version" : @1, @"producer" : @"ShadowHarness",
			@"run_id" : context[@"run_id"] ?: @"", @"row_id" : context[@"row_id"] ?: @"",
			@"row_type" : @"jailbroken", @"requested_mode" : mode ?: @"",
			@"nonce" : context[@"nonce"] ?: @"",
			@"probe_revision" : context[@"probe_revision"] ?: @"",
			@"canary" : canary,
			@"observations" : @{ @"aggregate" : @"SETUP-FAIL", @"error" : @"report generation failed" },
			@"producer_exit" : @2,
		};
	}
	NSString* nonce = report[@"nonce"];
	if(!report || !dir || !nonce.length || ![NSJSONSerialization isValidJSONObject:report]) {
		return NO;
	}
	NSData* data = [NSJSONSerialization dataWithJSONObject:report options:0 error:nil];
	NSString* path = [dir stringByAppendingPathComponent:
		[NSString stringWithFormat:@"ShadowDiagnostics-%@.json", nonce]];
	return ShdwWriteEvidenceData(data, path);
}

- (void)copyDiagnostics:(id)sender {
	[UIPasteboard generalPasteboard].string = [self diagnosticsString];
}

@end
