#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "SHDWDetectorLogListController.h"
#import "SHDWAppListController.h"

#import <Preferences/PSSpecifier.h>
#import <Preferences/PSTableCell.h>
#import <Shadow/Settings.h>
#import <AltList/LSApplicationProxy+AltList.h>

// Private UIKit SPI used by the existing Safe Mode pane for native app icons.
@interface UIImage (SHDWDetectorIcon)
+ (UIImage *)_applicationIconImageForBundleIdentifier:(NSString *)bundleID format:(int)format scale:(CGFloat)scale;
@end

@implementation SHDWDetectorLogListController {
	NSUserDefaults* prefs;
	NSMutableArray* entrySpecifiers;
	NSMutableDictionary* nameCache;
	NSMutableDictionary* iconCache;
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

	// The log link on an app's settings page reuses this controller. A child
	// pushed from the global app list already has filterBundleID assigned.
	if(!self.filterBundleID) {
		for(UIViewController* controller in self.navigationController.viewControllers) {
			if([controller isKindOfClass:[SHDWAppListController class]]) {
				self.filterBundleID = [(SHDWAppListController *)controller applicationID];
				break;
			}
		}
	}

	if(self.filterBundleID) {
		self.title = [self displayNameForBundleID:self.filterBundleID];
	}

	// Probes can arrive while the pane is open.
	[self reloadLogEntries];
}

- (NSString *)localized:(NSString *)key fallback:(NSString *)fallback {
	return [[NSBundle bundleForClass:[self class]] localizedStringForKey:key value:fallback table:@"DetectorLog"];
}

// Entries are "yyyy-MM-dd HH:mm:ss  reason  bundleID". Invalid legacy rows
// stay visible as raw text instead of disappearing.
- (NSDictionary *)recordForRawEntry:(id)value {
	if(![value isKindOfClass:[NSString class]]) {
		return nil;
	}

	NSString* raw = value;
	NSArray* fields = [raw componentsSeparatedByString:@"  "];
	if(fields.count != 3 || [fields[0] length] == 0 || [fields[1] length] == 0 || [fields[2] length] == 0) {
		return @{ @"raw" : raw };
	}

	return @{
		@"raw" : raw,
		@"timestamp" : fields[0],
		@"reason" : fields[1],
		@"bundleID" : fields[2],
	};
}

- (NSArray<NSDictionary *> *)records {
	NSMutableArray* records = [NSMutableArray new];
	for(id value in [prefs arrayForKey:@"DetectorLog"]) {
		NSDictionary* record = [self recordForRawEntry:value];
		if(record) {
			[records addObject:record];
		}
	}
	return records;
}

- (NSArray<NSDictionary *> *)filteredRecords {
	NSArray* records = [self records];
	if(!self.filterBundleID) {
		return records;
	}

	NSMutableArray* filtered = [NSMutableArray new];
	for(NSDictionary* record in records) {
		if([record[@"bundleID"] isEqualToString:self.filterBundleID]) {
			[filtered addObject:record];
		}
	}
	return filtered;
}

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

- (UIImage *)iconForBundleID:(NSString *)bundleID {
	UIImage* icon = iconCache[bundleID];
	if(!icon && [UIImage respondsToSelector:@selector(_applicationIconImageForBundleIdentifier:format:scale:)]) {
		icon = [UIImage _applicationIconImageForBundleIdentifier:bundleID format:2 scale:[UIScreen mainScreen].scale];
		if(icon) {
			iconCache[bundleID] = icon;
		}
	}
	return icon;
}

- (NSString *)eventCountText:(NSUInteger)count {
	if(count == 1) {
		return [self localized:@"EVENT_COUNT_ONE" fallback:@"1 event"];
	}
	return [NSString stringWithFormat:[self localized:@"EVENT_COUNT_MANY" fallback:@"%lu events"], (unsigned long)count];
}

// One summary per app, newest activity first. The ISO-like timestamp format
// sorts lexicographically, so the stored string is enough.
- (NSArray<NSDictionary *> *)applicationSummaries {
	NSMutableDictionary* byBundleID = [NSMutableDictionary new];
	NSMutableArray* malformed = [NSMutableArray new];

	for(NSDictionary* record in [self records]) {
		NSString* bundleID = record[@"bundleID"];
		if(!bundleID) {
			[malformed addObject:record];
			continue;
		}

		NSMutableDictionary* summary = byBundleID[bundleID];
		if(!summary) {
			summary = [@{ @"bundleID" : bundleID, @"count" : @0 } mutableCopy];
			byBundleID[bundleID] = summary;
		}
		summary[@"count"] = @([summary[@"count"] unsignedIntegerValue] + 1);
		summary[@"latest"] = record;
	}

	NSMutableArray* summaries = [[byBundleID allValues] mutableCopy];
	[summaries sortUsingComparator:^NSComparisonResult(NSDictionary* a, NSDictionary* b) {
		NSString* aTime = a[@"latest"][@"timestamp"] ?: @"";
		NSString* bTime = b[@"latest"][@"timestamp"] ?: @"";
		NSComparisonResult timeOrder = [bTime compare:aTime];
		if(timeOrder != NSOrderedSame) {
			return timeOrder;
		}
		return [[self displayNameForBundleID:a[@"bundleID"]] localizedCaseInsensitiveCompare:[self displayNameForBundleID:b[@"bundleID"]]];
	}];

	// Preserve malformed legacy rows after the application list.
	for(NSDictionary* record in [malformed reverseObjectEnumerator]) {
		[summaries addObject:record];
	}
	return summaries;
}

- (PSSpecifier *)summarySpecifier:(NSDictionary *)summary {
	NSString* bundleID = summary[@"bundleID"];
	NSDictionary* latest = summary[@"latest"];
	NSString* detail = [NSString stringWithFormat:@"%@ · %@ · %@",
		[self eventCountText:[summary[@"count"] unsignedIntegerValue]],
		latest[@"timestamp"], latest[@"reason"]];

	PSSpecifier* spec = [PSSpecifier preferenceSpecifierNamed:[self displayNameForBundleID:bundleID] target:self set:NULL get:NULL detail:nil cell:PSStaticTextCell edit:nil];
	[spec setProperty:@"SHDWDetectorLogApp" forKey:@"id"];
	[spec setProperty:@YES forKey:@"enabled"];
	[spec setProperty:bundleID forKey:@"logBundleID"];
	[spec setProperty:detail forKey:@"entryDetail"];
	return spec;
}

- (PSSpecifier *)eventSpecifier:(NSDictionary *)record {
	NSString* reason = record[@"reason"] ?: record[@"raw"];
	PSSpecifier* spec = [PSSpecifier preferenceSpecifierNamed:reason target:self set:NULL get:NULL detail:nil cell:PSStaticTextCell edit:nil];
	[spec setProperty:@"SHDWDetectorLogEvent" forKey:@"id"];
	[spec setProperty:@YES forKey:@"enabled"];
	[spec setProperty:record[@"raw"] forKey:@"eventRaw"];
	if(record[@"timestamp"]) {
		[spec setProperty:record[@"timestamp"] forKey:@"entryDetail"];
		[spec setProperty:record[@"reason"] forKey:@"eventReason"];
		[spec setProperty:record[@"bundleID"] forKey:@"eventBundleID"];
	}
	return spec;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
	PSSpecifier* specifier = [self specifierAtIndexPath:indexPath];
	NSString* bundleID = [specifier propertyForKey:@"logBundleID"];
	NSString* raw = [specifier propertyForKey:@"eventRaw"];

	if(bundleID || raw) {
		NSString* reuse = bundleID ? @"SHDWDetectorLogAppCell" : @"SHDWDetectorLogEventCell";
		PSTableCell* cell = [[PSTableCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:reuse specifier:specifier];
		cell.textLabel.text = [specifier name];
		cell.detailTextLabel.text = [specifier propertyForKey:@"entryDetail"];
		cell.selectionStyle = UITableViewCellSelectionStyleDefault;

		if(bundleID) {
			UIImage* icon = [self iconForBundleID:bundleID];
			if(icon) {
				cell.imageView.image = icon;
				cell.imageView.layer.cornerRadius = 6.0;
				cell.imageView.layer.masksToBounds = YES;
			}
			cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
			cell.accessibilityLabel = [NSString stringWithFormat:@"%@, %@", [specifier name], [specifier propertyForKey:@"entryDetail"]];
			cell.accessibilityHint = [self localized:@"OPEN_APP_HINT" fallback:@"Shows this application's detector activity"];
		} else {
			cell.accessoryType = UITableViewCellAccessoryDetailButton;
			cell.accessibilityLabel = cell.detailTextLabel.text.length > 0
				? [NSString stringWithFormat:@"%@, %@", [specifier name], cell.detailTextLabel.text]
				: [specifier name];
			cell.accessibilityHint = [self localized:@"OPEN_EVENT_HINT" fallback:@"Shows event details"];
		}

		return cell;
	}

	return [super tableView:tableView cellForRowAtIndexPath:indexPath];
}

- (void)showEventDetails:(PSSpecifier *)specifier {
	NSString* raw = [specifier propertyForKey:@"eventRaw"];
	if(!raw) {
		return;
	}

	NSString* bundleID = [specifier propertyForKey:@"eventBundleID"] ?: self.filterBundleID;
	NSString* timestamp = [specifier propertyForKey:@"entryDetail"] ?: @"—";
	NSString* name = bundleID ? [self displayNameForBundleID:bundleID] : @"—";
	NSString* message = [NSString stringWithFormat:[self localized:@"EVENT_DETAIL_FORMAT" fallback:@"Application: %@\nBundle ID: %@\nDetected: %@"], name, bundleID ?: @"—", timestamp];
	UIAlertController* alert = [UIAlertController alertControllerWithTitle:[specifier name] message:message preferredStyle:UIAlertControllerStyleAlert];

	[alert addAction:[UIAlertAction actionWithTitle:[self localized:@"COPY_EVENT" fallback:@"Copy"] style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
		[UIPasteboard generalPasteboard].string = raw;
	}]];
	[alert addAction:[UIAlertAction actionWithTitle:[self localized:@"DONE" fallback:@"Done"] style:UIAlertActionStyleCancel handler:nil]];
	[self presentViewController:alert animated:YES completion:nil];
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
	PSSpecifier* specifier = [self specifierAtIndexPath:indexPath];
	NSString* bundleID = [specifier propertyForKey:@"logBundleID"];

	if(bundleID) {
		[tableView deselectRowAtIndexPath:indexPath animated:YES];
		SHDWDetectorLogListController* controller = [SHDWDetectorLogListController new];
		controller.filterBundleID = bundleID;
		controller.title = [self displayNameForBundleID:bundleID];
		[self.navigationController pushViewController:controller animated:YES];
		return;
	}

	if([specifier propertyForKey:@"eventRaw"]) {
		[tableView deselectRowAtIndexPath:indexPath animated:YES];
		[self showEventDetails:specifier];
		return;
	}

	[super tableView:tableView didSelectRowAtIndexPath:indexPath];
}

- (void)tableView:(UITableView *)tableView accessoryButtonTappedForRowWithIndexPath:(NSIndexPath *)indexPath {
	PSSpecifier* specifier = [self specifierAtIndexPath:indexPath];
	if([specifier propertyForKey:@"eventRaw"]) {
		[self showEventDetails:specifier];
	}
}

- (void)reloadLogEntries {
	NSArray* records = self.filterBundleID ? [self filteredRecords] : [self applicationSummaries];
	PSSpecifier* entriesGroup = [self specifierForID:@"DetectorLogEntriesGroup"];
	entriesGroup.name = [self localized:self.filterBundleID ? @"ACTIVITY" : @"APPLICATIONS"
		fallback:self.filterBundleID ? @"Activity" : @"Applications"];

	for(PSSpecifier* spec in entrySpecifiers) {
		[self removeSpecifier:spec];
	}
	[entrySpecifiers removeAllObjects];

	if(records.count == 0) {
		NSString* fallback = self.filterBundleID ? @"No detector activity recorded for this app" : @"No detector activity recorded";
		PSSpecifier* empty = [PSSpecifier preferenceSpecifierNamed:[self localized:self.filterBundleID ? @"NO_APP_ACTIVITY" : @"NO_ACTIVITY" fallback:fallback] target:self set:NULL get:NULL detail:nil cell:PSStaticTextCell edit:nil];
		[empty setProperty:@"SHDWDetectorLogEntry" forKey:@"id"];
		[empty setProperty:@YES forKey:@"enabled"];
		[entrySpecifiers addObject:empty];
		[self insertSpecifier:empty atIndex:1];
		return;
	}

	NSInteger index = 1;
	for(NSDictionary* record in self.filterBundleID ? [records reverseObjectEnumerator] : records) {
		PSSpecifier* spec = record[@"bundleID"] && record[@"latest"]
			? [self summarySpecifier:record]
			: [self eventSpecifier:record];
		[entrySpecifiers addObject:spec];
		[self insertSpecifier:spec atIndex:index++];
	}
}

- (void)clearLog:(id)sender {
	UIAlertController* alert = [UIAlertController alertControllerWithTitle:[self localized:@"CLEAR_CONFIRM_TITLE" fallback:@"Clear Detector Log?"] message:[self localized:@"CLEAR_CONFIRM_MSG" fallback:@"This removes all recorded detector activity. This cannot be undone."] preferredStyle:UIAlertControllerStyleAlert];

	[alert addAction:[UIAlertAction actionWithTitle:[self localized:@"CLEAR_CANCEL" fallback:@"Cancel"] style:UIAlertActionStyleCancel handler:nil]];
	[alert addAction:[UIAlertAction actionWithTitle:[self localized:@"CLEAR_CONFIRM" fallback:@"Clear"] style:UIAlertActionStyleDestructive handler:^(UIAlertAction* action) {
		if(self.filterBundleID) {
			// ponytail: interprocess RMW race with app-side appends; move writes
// to a dedicated store if detector-log volume ever makes lost entries material.
			NSMutableArray* kept = [NSMutableArray new];
			for(id value in [prefs arrayForKey:@"DetectorLog"]) {
				NSDictionary* record = [self recordForRawEntry:value];
				if(![record[@"bundleID"] isEqualToString:self.filterBundleID]) {
					[kept addObject:value];
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
	NSMutableArray* lines = [NSMutableArray new];
	for(NSDictionary* record in [self filteredRecords]) {
		[lines addObject:record[@"raw"]];
	}
	if(lines.count == 0) {
		return;
	}

	UIActivityViewController* avc = [[UIActivityViewController alloc] initWithActivityItems:@[[lines componentsJoinedByString:@"\n"]] applicationActivities:nil];
	avc.popoverPresentationController.sourceView = self.view;
	avc.popoverPresentationController.sourceRect = self.view.bounds;
	[self presentViewController:avc animated:YES completion:nil];
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
		entrySpecifiers = [NSMutableArray new];
		nameCache = [NSMutableDictionary new];
		iconCache = [NSMutableDictionary new];
	}
	return self;
}
@end
