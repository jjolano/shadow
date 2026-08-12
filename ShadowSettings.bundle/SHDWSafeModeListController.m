#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "SHDWSafeModeListController.h"

#import <Preferences/PSSpecifier.h>
#import <Preferences/PSTableCell.h>
#import <Shadow/Settings.h>
#import <AltList/LSApplicationProxy+AltList.h>

#import <time.h>

#import "../common.h"   // SHADOW_CRASH_THRESHOLD, SHADOW_CRASH_DECAY_SECS

// Prefix of the per-app crash-counter keys the watchdog writes
// (shdw_crash_counter_key in common.h: "CrashCount.<bundleID>").
static NSString* const kCrashCountPrefix = @"CrashCount.";

@implementation SHDWSafeModeListController {
	NSUserDefaults* prefs;
	NSMutableArray* entrySpecifiers;
	NSMutableDictionary* nameCache;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"SafeMode" target:self];
	}

	return _specifiers;
}

- (void)viewDidLoad {
	[super viewDidLoad];
	[self reloadEntries];
}

- (void)viewWillAppear:(BOOL)animated {
	[super viewWillAppear:animated];
	// A counter can appear/advance while the pane is open (an app crash-loops
	// in the background), so refresh on every appearance.
	[self reloadEntries];
}

- (NSString *)localized:(NSString *)key fallback:(NSString *)fallback {
	return [[NSBundle bundleForClass:[self class]] localizedStringForKey:key value:fallback table:@"SafeMode"];
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

// One (bundleID, count, skipped) record per crash-counter key. Mirrors the
// watchdog's own read (Shadow.dylib): parse "count:timestamp", treat a counter
// older than the decay window as stale (the watchdog would reset it on the next
// launch, so it is effectively "retrying", not skipped).
- (NSArray<NSDictionary *> *)crashRecords {
	NSMutableArray* records = [NSMutableArray new];
	NSDictionary* all = [prefs dictionaryRepresentation];

	for(NSString* key in all) {
		if(![key hasPrefix:kCrashCountPrefix]) {
			continue;
		}

		NSString* bundleID = [key substringFromIndex:kCrashCountPrefix.length];
		NSString* value = all[key];
		if(![value isKindOfClass:[NSString class]]) {
			continue;
		}

		NSArray* parts = [value componentsSeparatedByString:@":"];
		if(parts.count != 2) {
			continue;
		}

		int count = [parts[0] intValue];
		long long ts = [parts[1] longLongValue];
		BOOL stale = (ts > 0 && (long long)time(NULL) - ts > SHADOW_CRASH_DECAY_SECS);
		int effective = stale ? 0 : count;

		[records addObject:@{
			@"key" : key,
			@"bundleID" : bundleID,
			@"count" : @(effective),
			@"skipped" : @(effective >= SHADOW_CRASH_THRESHOLD),
		}];
	}

	// Skipped apps first (the ones the user most likely wants to clear), then
	// by descending count, then by name for stability.
	[records sortUsingComparator:^NSComparisonResult(NSDictionary* a, NSDictionary* b) {
		if([a[@"skipped"] boolValue] != [b[@"skipped"] boolValue]) {
			return [a[@"skipped"] boolValue] ? NSOrderedAscending : NSOrderedDescending;
		}
		if(![a[@"count"] isEqual:b[@"count"]]) {
			return [b[@"count"] compare:a[@"count"]];
		}
		return [[self displayNameForBundleID:a[@"bundleID"]] localizedCaseInsensitiveCompare:[self displayNameForBundleID:b[@"bundleID"]]];
	}];

	return records;
}

- (PSSpecifier *)entrySpecifierForRecord:(NSDictionary *)record {
	NSString* bundleID = record[@"bundleID"];
	NSString* name = [self displayNameForBundleID:bundleID];

	// Tapping the row clears just this app's counter — handled in
	// tableView:didSelectRowAtIndexPath: (a PSLinkCell would try to push a
	// child pane; a plain selectable row + explicit handler is what we want).
	// The detail text carries the status.
	PSSpecifier* entry = [PSSpecifier preferenceSpecifierNamed:name target:self set:NULL get:NULL detail:nil cell:PSStaticTextCell edit:nil];
	[entry setProperty:@"SHDWSafeModeEntry" forKey:@"id"];
	[entry setProperty:@YES forKey:@"enabled"];
	[entry setProperty:record[@"key"] forKey:@"crashKey"];
	[entry setProperty:bundleID forKey:@"crashBundleID"];

	NSString* status = [record[@"skipped"] boolValue]
		? [NSString stringWithFormat:[self localized:@"STATUS_SKIPPED_FMT" fallback:@"Skipped — %d crashes"], [record[@"count"] intValue]]
		: [NSString stringWithFormat:[self localized:@"STATUS_COUNTING_FMT" fallback:@"%d/%d crashes"], [record[@"count"] intValue], SHADOW_CRASH_THRESHOLD];
	[entry setProperty:status forKey:@"entryDetail"];

	return entry;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
	PSSpecifier* specifier = [self specifierAtIndexPath:indexPath];
	NSString* detail = [specifier propertyForKey:@"entryDetail"];

	if(detail) {
		PSTableCell* cell = [[PSTableCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"SHDWSafeModeEntryCell" specifier:specifier];
		cell.textLabel.text = [specifier name];
		cell.textLabel.numberOfLines = 0;
		cell.detailTextLabel.text = detail;
		// Selectable (tap clears the counter) only for real entries; the empty
		// state carries no crashKey and stays inert.
		cell.selectionStyle = [specifier propertyForKey:@"crashKey"] ? UITableViewCellSelectionStyleDefault : UITableViewCellSelectionStyleNone;
		return cell;
	}

	return [super tableView:tableView cellForRowAtIndexPath:indexPath];
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
	PSSpecifier* specifier = [self specifierAtIndexPath:indexPath];

	if([specifier propertyForKey:@"crashKey"]) {
		[tableView deselectRowAtIndexPath:indexPath animated:YES];
		[self clearOne:specifier];
		return;
	}

	[super tableView:tableView didSelectRowAtIndexPath:indexPath];
}

// Rebuilds the dynamic rows from the crash counters. The static header +
// Clear All button come from SafeMode.plist; entries are inserted after the
// header group.
- (void)reloadEntries {
	NSArray* records = [self crashRecords];

	for(PSSpecifier* spec in entrySpecifiers) {
		[self removeSpecifier:spec];
	}
	[entrySpecifiers removeAllObjects];

	NSInteger index = 1;

	if(records.count == 0) {
		PSSpecifier* empty = [PSSpecifier preferenceSpecifierNamed:[self localized:@"NO_APPS" fallback:@"No apps in safe mode"] target:self set:NULL get:NULL detail:nil cell:PSStaticTextCell edit:nil];
		[empty setProperty:@"SHDWSafeModeEntry" forKey:@"id"];
		[empty setProperty:@YES forKey:@"enabled"];
		[entrySpecifiers addObject:empty];
		[self insertSpecifier:empty atIndex:index];
		return;
	}

	for(NSDictionary* record in records) {
		PSSpecifier* spec = [self entrySpecifierForRecord:record];
		[entrySpecifiers addObject:spec];
		[self insertSpecifier:spec atIndex:index++];
	}
}

- (void)clearOne:(PSSpecifier *)specifier {
	NSString* key = [specifier propertyForKey:@"crashKey"];
	NSString* bundleID = [specifier propertyForKey:@"crashBundleID"];
	if(!key) {
		return;
	}

	NSString* name = [self displayNameForBundleID:bundleID];
	UIAlertController* alert = [UIAlertController alertControllerWithTitle:[NSString stringWithFormat:[self localized:@"CLEAR_ONE_TITLE_FMT" fallback:@"Retry %@?"], name] message:[self localized:@"CLEAR_ONE_MSG" fallback:@"Shadow will try loading into this app again on its next launch."] preferredStyle:UIAlertControllerStyleAlert];

	[alert addAction:[UIAlertAction actionWithTitle:[self localized:@"CANCEL" fallback:@"Cancel"] style:UIAlertActionStyleCancel handler:nil]];
	[alert addAction:[UIAlertAction actionWithTitle:[self localized:@"RETRY" fallback:@"Retry"] style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
		[prefs removeObjectForKey:key];
		[prefs synchronize];
		[self reloadEntries];
	}]];

	[self presentViewController:alert animated:YES completion:nil];
}

- (void)clearAll:(id)sender {
	NSArray* records = [self crashRecords];
	if(records.count == 0) {
		return;
	}

	UIAlertController* alert = [UIAlertController alertControllerWithTitle:[self localized:@"CLEAR_ALL_TITLE" fallback:@"Retry all apps?"] message:[self localized:@"CLEAR_ALL_MSG" fallback:@"Clears every crash counter. Shadow will try loading into these apps again on their next launch."] preferredStyle:UIAlertControllerStyleAlert];

	[alert addAction:[UIAlertAction actionWithTitle:[self localized:@"CANCEL" fallback:@"Cancel"] style:UIAlertActionStyleCancel handler:nil]];
	[alert addAction:[UIAlertAction actionWithTitle:[self localized:@"RETRY_ALL" fallback:@"Retry All"] style:UIAlertActionStyleDestructive handler:^(UIAlertAction* action) {
		for(NSDictionary* record in records) {
			[prefs removeObjectForKey:record[@"key"]];
		}
		[prefs synchronize];
		[self reloadEntries];
	}]];

	[self presentViewController:alert animated:YES completion:nil];
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
