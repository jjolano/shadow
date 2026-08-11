#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "SHDWDetectorLogListController.h"
#import "SHDWAppListController.h"

#import <Preferences/PSSpecifier.h>
#import <Preferences/PSTableCell.h>
#import <Shadow/Settings.h>

@implementation SHDWDetectorLogListController {
	NSUserDefaults* prefs;
	NSMutableArray* entrySpecifiers;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"DetectorLog" target:self];
	}

	return _specifiers;
}

- (void)viewDidLoad {
	[super viewDidLoad];

	[self reloadLogEntries];
}

- (void)viewWillAppear:(BOOL)animated {
	[super viewWillAppear:animated];

	// When pushed from a per-app page, scope the log to that app.
	if(!self.filterBundleID) {
		for(UIViewController* controller in self.navigationController.viewControllers) {
			if([controller isKindOfClass:[SHDWAppListController class]]) {
				self.filterBundleID = [(SHDWAppListController *)controller applicationID];
				break;
			}
		}
	}

	// The log can grow while the pane is open (probes fire in other apps),
	// so refresh on every appearance.
	[self reloadLogEntries];
}

- (NSString *)localized:(NSString *)key fallback:(NSString *)fallback {
	return [[NSBundle bundleForClass:[self class]] localizedStringForKey:key value:fallback table:@"DetectorLog"];
}

// Entries are "yyyy-MM-dd HH:mm:ss  reason  bundleID"; the bundle identifier
// is the last two-space-separated field and never contains spaces.
- (NSArray *)filteredLogEntries {
	NSArray* log = [prefs arrayForKey:@"DetectorLog"];

	if(!self.filterBundleID) {
		return log;
	}

	NSMutableArray* filtered = [NSMutableArray new];
	for(NSString* entry in log) {
		if([[[entry componentsSeparatedByString:@"  "] lastObject] isEqualToString:self.filterBundleID]) {
			[filtered addObject:entry];
		}
	}

	return filtered;
}

// Rebuilds the log-entry cells from the prefs array. The static specifiers
// (group header + clear button) come from DetectorLog.plist; the entries are
// dynamic, so they are inserted after the header group.
- (void)reloadLogEntries {
	NSArray* log = [self filteredLogEntries];

	// Remove previously inserted entry cells. Every entry shares the
	// "SHDWDetectorLogEntry" identifier, and specifiersForIDs: resolves at
	// most one specifier per id, so track the inserted objects instead.
	for(PSSpecifier* spec in entrySpecifiers) {
		[self removeSpecifier:spec];
	}
	[entrySpecifiers removeAllObjects];

	if(log.count == 0) {
		PSSpecifier* empty = [PSSpecifier preferenceSpecifierNamed:[[NSBundle bundleForClass:[self class]] localizedStringForKey:@"NO_ACTIVITY" value:@"No detector activity recorded" table:@"DetectorLog"] target:self set:NULL get:NULL detail:nil cell:PSStaticTextCell edit:nil];
		[empty setProperty:@"SHDWDetectorLogEntry" forKey:@"id"];
		[empty setProperty:@YES forKey:@"enabled"];
		[entrySpecifiers addObject:empty];
		[self insertSpecifier:empty atIndex:1];
		return;
	}

	// Newest first: iterate oldest-to-newest so each insert at index 1
	// pushes the previous entry down.
	for(NSInteger i = 0; i < log.count; i++) {
		PSSpecifier* entry = [PSSpecifier preferenceSpecifierNamed:log[i] target:self set:NULL get:NULL detail:nil cell:PSStaticTextCell edit:nil];
		[entry setProperty:@"SHDWDetectorLogEntry" forKey:@"id"];
		[entry setProperty:@YES forKey:@"enabled"];
		[entrySpecifiers addObject:entry];
		[self insertSpecifier:entry atIndex:1];
	}
}

- (void)clearLog:(id)sender {
	UIAlertController* alert = [UIAlertController alertControllerWithTitle:[self localized:@"CLEAR_CONFIRM_TITLE" fallback:@"Clear Detector Log?"] message:[self localized:@"CLEAR_CONFIRM_MSG" fallback:@"This removes all recorded detector activity. This cannot be undone."] preferredStyle:UIAlertControllerStyleAlert];

	[alert addAction:[UIAlertAction actionWithTitle:[self localized:@"CLEAR_CANCEL" fallback:@"Cancel"] style:UIAlertActionStyleCancel handler:nil]];
	[alert addAction:[UIAlertAction actionWithTitle:[self localized:@"CLEAR_CONFIRM" fallback:@"Clear"] style:UIAlertActionStyleDestructive handler:^(UIAlertAction* action) {
		if(self.filterBundleID) {
			// Per-app clear: drop only the matching entries, keep the rest.
			// ponytail: interprocess RMW race with app-side appends; a proper fix needs a shared lock/daemon writer, not worth it for a log pane
			NSArray* log = [prefs arrayForKey:@"DetectorLog"];
			NSMutableArray* kept = [NSMutableArray new];
			for(NSString* entry in log) {
				if(![[[entry componentsSeparatedByString:@"  "] lastObject] isEqualToString:self.filterBundleID]) {
					[kept addObject:entry];
				}
			}
			[prefs setObject:kept forKey:@"DetectorLog"];
		} else {
			[prefs removeObjectForKey:@"DetectorLog"];
		}
		[prefs synchronize];
		[self reloadLogEntries];
	}]];

	[self presentViewController:alert animated:YES completion:nil];
}

- (void)shareLog:(id)sender {
	NSArray* log = [self filteredLogEntries];

	if(log.count == 0) {
		return;
	}

	NSString* text = [log componentsJoinedByString:@"\n"];
	UIActivityViewController* avc = [[UIActivityViewController alloc] initWithActivityItems:@[text] applicationActivities:nil];
	avc.popoverPresentationController.sourceView = self.view;
	avc.popoverPresentationController.sourceRect = self.view.bounds;
	[self presentViewController:avc animated:YES completion:nil];
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
		entrySpecifiers = [NSMutableArray new];
	}

	return self;
}
@end