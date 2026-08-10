#import "StatusViewController.h"

#import <Shadow.h>
#import <Shadow/JBPath.h>
#import <Shadow/Settings.h>

#import "Battery.h"

// Shadow's own prefs plist (mirrors common.h SHADOW_PREFS_PLIST; kept local
// so the harness does not depend on the framework source tree).
static NSString* const kShadowPrefsPlist = @"/var/mobile/Library/Preferences/me.jjolano.shadow.plist";

// Same argv[0] probe the stub's ctor evaluates (Shadow.dylib/dylib.x) —
// shown in the why rows so a user can see the path Shadow's loader saw.
extern char*** _NSGetArgv();

// ShadowSettings class only exists when Shadow.framework is loaded. The
// harness links the framework, so it is present at runtime; fall back to a
// raw NSUserDefaults suite read for the not-loaded case.
static NSUserDefaults* shdw_prefs(void) {
	return [[NSUserDefaults alloc] initWithSuiteName:kShadowPrefsPlist];
}

static NSDictionary* shdw_shadow_settings_for(NSString* bundleID) {
	Class settingsClass = NSClassFromString(@"ShadowSettings");
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

@implementation StatusViewController {
	NSArray<NSDictionary*>* _sections;
	BOOL _devMode;
}

- (void)viewDidLoad {
	[super viewDidLoad];

	self.title = @"Shadow Harness";
	self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
		initWithTitle:@"Copy diagnostics" style:UIBarButtonItemStylePlain
		target:self action:@selector(copyDiagnostics:)];

	_devMode = NO;
	_sections = [self buildSectionsIncludingBattery:NO];
}

- (void)viewWillAppear:(BOOL)animated {
	[super viewWillAppear:animated];
	// Re-run the probes every time the view appears — cheap, and the
	// diagnostics stay fresh.
	_sections = [self buildSectionsIncludingBattery:NO];
	[self.tableView reloadData];
}

#pragma mark - Model

- (NSArray<NSDictionary*>*)buildSectionsIncludingBattery:(BOOL)includeBattery {
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

// Row helpers.
static NSDictionary* row(NSString* text, NSString* detail) {
	return detail.length ? @{ @"text" : text, @"detail" : detail } : @{ @"text" : text };
}

- (NSDictionary*)shadowStatusSection {
	NSMutableArray* rows = [NSMutableArray new];

	// The harness links Shadow.framework directly, so class presence says
	// nothing about whether Shadow is actually filtering this process. The
	// hooks payload (ShadowCore.dylib) is the primary answer.
	BOOL payloadActive = ShdwIsShadowCoreLoaded();
	BOOL enginePresent = NSClassFromString(@"Shadow") != nil;

	if(payloadActive) {
		Shadow* shadow = [NSClassFromString(@"Shadow") sharedInstance];

		[rows addObject:row(@"Shadow active (hooks payload)", @"YES")];
		[rows addObject:row(@"Engine present (framework)", @"YES")];
		[rows addObject:row(@"Rootless", shadow.rootless ? @"yes" : @"no")];
		[rows addObject:row(@"Has app sandbox", shadow.hasAppSandbox ? @"yes" : @"no")];
		[rows addObject:row(@"Bundle path", shadow.bundlePath)];
		[rows addObject:row(@"Home path", shadow.homePath)];
	} else {
		[rows addObject:row(@"Shadow active (hooks payload)", @"NO")];
		[rows addObject:row(@"Engine present (framework)", enginePresent ? @"YES" : @"NO")];

		// "Why" rows: the path the stub's gate evaluated, then this app's
		// own entry in Shadow's prefs. The keys are App_Enabled (per-app
		// override) and Global_Enabled (always-on); with neither set, the
		// stub skips this app by design.
		[rows addObject:row(@"Executable path", @(**_NSGetArgv()))];

		NSString* bundleID = [NSBundle mainBundle].bundleIdentifier;
		NSUserDefaults* prefs = shdw_prefs();
		NSDictionary* appSettings = bundleID ? [prefs objectForKey:bundleID] : nil;
		NSNumber* appEnabled = appSettings ? appSettings[@"App_Enabled"] : nil;
		NSNumber* globalEnabled = [prefs objectForKey:@"Global_Enabled"];

		if(appSettings) {
			[rows addObject:row(@"Per-app override",
				[NSString stringWithFormat:@"present (App_Enabled=%@)", appEnabled ? appEnabled : @"(unset)"])];
		} else {
			[rows addObject:row(@"Per-app override", @"absent")];
		}
		[rows addObject:row(@"Global_Enabled", globalEnabled ? [globalEnabled boolValue] ? @"YES" : @"NO" : @"(unreadable)")];

		if([appEnabled boolValue]) {
			[rows addObject:row(@"Filter enabled", @"App_Enabled=YES — Shadow should be active")];
		} else if([globalEnabled boolValue]) {
			[rows addObject:row(@"Filter enabled", @"Global_Enabled=YES — Shadow should be active")];
		} else {
			[rows addObject:row(@"Filter disabled",
				@"App_Enabled and Global_Enabled both off — Shadow skips this app")];
		}
		[rows addObject:row(@"Hint", @"Check Shadow settings for this app")];
	}

	return @{ @"title" : @"Shadow status", @"rows" : rows };
}

- (NSDictionary*)thisAppSection {
	NSString* bundleID = [NSBundle mainBundle].bundleIdentifier;
	NSUserDefaults* prefs = shdw_prefs();
	NSDictionary* appSettings = bundleID ? [prefs objectForKey:bundleID] : nil;
	NSNumber* globalEnabled = [prefs objectForKey:@"Global_Enabled"];

	// Shadow's per-app model is binary (see Shadow.dylib/dylib.x): the app
	// is filtered iff App_Enabled (per-app override) or Global_Enabled is
	// set. "Allowlisted"/"blocklisted" are not plist states in this version.
	BOOL appEnabled = [appSettings[@"App_Enabled"] boolValue];
	BOOL filtered = appEnabled || [globalEnabled boolValue];

	// Prefer ShadowSettings' merged view (defaults + per-app inheritance);
	// fall back to the raw suite when the class is unavailable.
	NSDictionary* merged = shdw_shadow_settings_for(bundleID);
	if(merged) {
		filtered = [merged[@"App_Enabled"] boolValue];
	}

	NSString* modeDetail = appEnabled ? @"App_Enabled=YES (per-app)" :
		[globalEnabled boolValue] ? @"Global_Enabled=YES" : @"neither key set";

	return @{ @"title" : @"This app", @"rows" : @[
		row(@"Bundle ID", bundleID ? bundleID : @"(nil)"),
		row(@"Filter mode", filtered ? [@"filtered — " stringByAppendingString:modeDetail] : [@"off — " stringByAppendingString:modeDetail]),
		row(@"Per-app override present?", appSettings ? @"yes" : @"no"),
	]};
}

- (NSDictionary*)rulesetSection {
	NSMutableArray* rows = [NSMutableArray new];

	if(!NSClassFromString(@"Shadow")) {
		[rows addObject:row(@"n/a", @"Shadow not loaded")];
		return @{ @"title" : @"Ruleset", @"rows" : rows };
	}

	NSString* rulesetsDir = JBPath(@"/Library/Shadow/Rulesets");
	NSArray<NSString*>* files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:rulesetsDir error:nil];
	files = [files sortedArrayUsingSelector:@selector(localizedStandardCompare:)];

	Class rulesetEngineClass = NSClassFromString(@"RulesetEngine");
	NSDateFormatter* dateFormatter = [NSDateFormatter new];
	dateFormatter.dateStyle = NSDateFormatterMediumStyle;
	dateFormatter.timeStyle = NSDateFormatterShortStyle;

	for(NSString* file in files) {
		// Compiled-ruleset caches (RulesetEngine writes these next to each
		// ruleset plist) are not rulesets.
		if([file hasSuffix:@"shadowcache"]) {
			continue;
		}

		NSString* fullPath = [rulesetsDir stringByAppendingPathComponent:file];
		NSDictionary* attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:fullPath error:nil];
		NSString* mtime = attrs[NSFileModificationDate] ? [dateFormatter stringFromDate:attrs[NSFileModificationDate]] : @"?";

		NSUInteger ruleCount = 0;
		if(rulesetEngineClass) {
			RulesetEngine* ruleset = [rulesetEngineClass rulesetWithURL:[NSURL fileURLWithPath:fullPath]];
			ruleCount = ruleset.payloadDictionary.count;
		}

		[rows addObject:row(file, [NSString stringWithFormat:@"%@ — %lu rules", mtime, (unsigned long)ruleCount])];
	}

	if(!rows.count) {
		[rows addObject:row(@"No rulesets", rulesetsDir)];
	}

	return @{ @"title" : @"Ruleset", @"rows" : rows };
}

- (NSDictionary*)canonicalSection {
	NSMutableArray* rows = [NSMutableArray new];
	for(NSDictionary* probe in ShdwCanonicalProbes()) {
		[rows addObject:row(probe[@"probe"],
			[NSString stringWithFormat:@"engine: %@", probe[@"verdict"]])];
	}
	return @{ @"title" : @"Canonical probes", @"rows" : rows };
}

- (NSDictionary*)devModeSection {
	NSMutableArray* rows = [NSMutableArray new];
	[rows addObject:@{ @"text" : @"Dev mode", @"kind" : @"switch", @"on" : @(_devMode) }];
	if(_devMode) {
		[rows addObject:row(@"Footnote", @"known/public techniques only — not proof of undetectability.")];
	}
	return @{ @"title" : @"Dev mode", @"rows" : rows };
}

- (NSDictionary*)batterySection {
	NSArray<NSDictionary*>* batteryRows = ShdwBatteryRows();

	NSUInteger fired = 0;
	for(NSDictionary* batteryRow in batteryRows) {
		if([batteryRow[@"fired"] boolValue]) {
			fired++;
		}
	}

	NSMutableArray* rows = [NSMutableArray new];
	[rows addObject:row(@"Detector fired",
		[NSString stringWithFormat:@"%lu/%lu probes fired", (unsigned long)fired, (unsigned long)batteryRows.count])];

	for(NSDictionary* batteryRow in batteryRows) {
		[rows addObject:row(batteryRow[@"name"],
			[NSString stringWithFormat:@"%@ — raw %@ / libc %@ / engine %@ — reason: %@",
				batteryRow[@"verdict"], batteryRow[@"raw"], batteryRow[@"filtered"],
				batteryRow[@"engine"], batteryRow[@"reason"]])];
	}

	return @{ @"title" : @"Detector battery", @"rows" : rows };
}

#pragma mark - Table view data source

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView {
	return _sections.count;
}

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section {
	return [_sections[section][@"rows"] count];
}

- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section {
	return _sections[section][@"title"];
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath {
	NSDictionary* rowModel = _sections[indexPath.section][@"rows"][indexPath.row];

	UITableViewCell* cell = [tableView dequeueReusableCellWithIdentifier:@"Cell"];
	if(!cell) {
		cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"Cell"];
		cell.textLabel.numberOfLines = 0;
		cell.detailTextLabel.numberOfLines = 0;
	}

	cell.textLabel.text = rowModel[@"text"];
	cell.detailTextLabel.text = rowModel[@"detail"];

	if([rowModel[@"kind"] isEqualToString:@"switch"]) {
		UISwitch* switchView = [UISwitch new];
		switchView.on = [rowModel[@"on"] boolValue];
		[switchView addTarget:self action:@selector(devModeChanged:) forControlEvents:UIControlEventValueChanged];
		cell.accessoryView = switchView;
		cell.selectionStyle = UITableViewCellSelectionStyleNone;
	} else {
		cell.accessoryView = nil;
		cell.selectionStyle = UITableViewCellSelectionStyleDefault;
	}

	return cell;
}

#pragma mark - Actions

- (void)devModeChanged:(UISwitch*)switchView {
	_devMode = switchView.on;
	_sections = [self buildSectionsIncludingBattery:NO];
	[self.tableView reloadData];
}

- (void)copyDiagnostics:(id)sender {
	NSArray<NSDictionary*>* fullSections = [self buildSectionsIncludingBattery:YES];
	[UIPasteboard generalPasteboard].string = ShdwDiagnosticsDump(fullSections);
}

@end
