#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "SHDWDetectorLogListController.h"
#import "SHDWAppListController.h"

#import <Preferences/PSSpecifier.h>
#import <Preferences/PSTableCell.h>
#import <Shadow/Settings.h>
#import <AltList/LSApplicationProxy+AltList.h>

@implementation SHDWDetectorLogListController {
	NSUserDefaults* prefs;
	NSMutableArray* entrySpecifiers;

	// bundleID -> display name, so a 100-entry reload hits LSApplicationProxy
	// once per app instead of once per entry.
	NSMutableDictionary* nameCache;
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

// App display name via AltList (same lookup the Apps page uses for its
// title), falling back to the raw bundle identifier.
- (NSString *)displayNameForBundleID:(NSString *)bundleID {
	NSString* name = nameCache[bundleID];

	if(!name) {
		name = [LSApplicationProxy applicationProxyForIdentifier:bundleID].atl_fastDisplayName;
		if(name.length == 0) {
			name = bundleID;
		}
		nameCache[bundleID] = name;
	}

	return name;
}

// One specifier per log line. A clean 3-field entry becomes a structured row
// (title = reason, subtitle = timestamp, rendered by cellForRow below);
// anything that doesn't split exactly keeps the raw string as its title and
// renders as a plain static-text row like before.
- (PSSpecifier *)entrySpecifierForRawEntry:(NSString *)raw {
	PSSpecifier* entry = [PSSpecifier preferenceSpecifierNamed:raw target:self set:NULL get:NULL detail:nil cell:PSStaticTextCell edit:nil];
	[entry setProperty:@"SHDWDetectorLogEntry" forKey:@"id"];
	[entry setProperty:@YES forKey:@"enabled"];

	NSArray* fields = [raw componentsSeparatedByString:@"  "];
	if(fields.count == 3 && [fields[0] length] > 0 && [fields[1] length] > 0 && [fields[2] length] > 0) {
		[entry setName:fields[1]];
		[entry setProperty:fields[0] forKey:@"entryDetail"];
	}

	return entry;
}

// Structured rows get a subtitle cell; everything else (the empty state,
// unparseable entries) uses the standard static-text cell from super.
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
	PSSpecifier* specifier = [self specifierAtIndexPath:indexPath];
	NSString* detail = [specifier propertyForKey:@"entryDetail"];

	if(detail) {
		PSTableCell* cell = [[PSTableCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"SHDWDetectorLogEntryCell" specifier:specifier];
		cell.textLabel.text = [specifier name];
		cell.textLabel.numberOfLines = 0;
		cell.detailTextLabel.text = detail;
		cell.selectionStyle = UITableViewCellSelectionStyleNone;
		return cell;
	}

	return [super tableView:tableView cellForRowAtIndexPath:indexPath];
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

	NSMutableArray* ordered = [NSMutableArray new];

	if(self.filterBundleID) {
		// Per-app page: the app is implied by where the user came from, so a
		// flat list of entries, newest first.
		for(NSString* entry in [log reverseObjectEnumerator]) {
			[ordered addObject:[self entrySpecifierForRawEntry:entry]];
		}
	} else {
		// Global page: group entries under per-app headers. Walking the log
		// newest-first yields groups ordered by most recent activity, with
		// the newest entry first inside each group.
		NSMutableArray* groupOrder = [NSMutableArray new];
		NSMutableDictionary* groups = [NSMutableDictionary new];

		for(NSString* entry in [log reverseObjectEnumerator]) {
			NSString* bundleID = [[entry componentsSeparatedByString:@"  "] lastObject];
			if(bundleID.length == 0) {
				bundleID = entry;
			}

			NSMutableArray* group = groups[bundleID];
			if(!group) {
				group = [NSMutableArray new];
				groups[bundleID] = group;
				[groupOrder addObject:bundleID];
			}
			[group addObject:[self entrySpecifierForRawEntry:entry]];
		}

		for(NSString* bundleID in groupOrder) {
			[ordered addObject:[PSSpecifier groupSpecifierWithName:[self displayNameForBundleID:bundleID]]];
			[ordered addObjectsFromArray:groups[bundleID]];
		}
	}

	// Insert after the static header group; the Share/Clear buttons are
	// pushed down below the entries.
	NSInteger index = 1;
	for(PSSpecifier* spec in ordered) {
		[entrySpecifiers addObject:spec];
		[self insertSpecifier:spec atIndex:index++];
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
		nameCache = [NSMutableDictionary new];
	}

	return self;
}
@end