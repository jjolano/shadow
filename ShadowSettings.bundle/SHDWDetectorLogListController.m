#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "SHDWDetectorLogListController.h"

#import <Preferences/PSSpecifier.h>
#import <Preferences/PSTableCell.h>
#import <Shadow/Settings.h>

@implementation SHDWDetectorLogListController {
	NSUserDefaults* prefs;
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

	// The log can grow while the pane is open (probes fire in other apps),
	// so refresh on every appearance.
	[self reloadLogEntries];
}

- (NSString *)localized:(NSString *)key fallback:(NSString *)fallback {
	return [[NSBundle bundleForClass:[self class]] localizedStringForKey:key value:fallback table:@"DetectorLog"];
}

// Rebuilds the log-entry cells from the prefs array. The static specifiers
// (group header + clear button) come from DetectorLog.plist; the entries are
// dynamic, so they are inserted after the header group.
- (void)reloadLogEntries {
	NSArray* log = [prefs arrayForKey:@"DetectorLog"];

	// Remove previously inserted entry cells (they carry the
	// "SHDWDetectorLogEntry" identifier).
	NSArray* existing = [self specifiersForIDs:@[@"SHDWDetectorLogEntry"]];

	for(PSSpecifier* spec in existing) {
		[self removeSpecifier:spec];
	}

	if(log.count == 0) {
		PSSpecifier* empty = [PSSpecifier preferenceSpecifierNamed:[[NSBundle bundleForClass:[self class]] localizedStringForKey:@"NO_ACTIVITY" value:@"No detector activity recorded" table:@"DetectorLog"] target:self set:NULL get:NULL detail:nil cell:PSStaticTextCell edit:nil];
		[empty setProperty:@"SHDWDetectorLogEntry" forKey:@"id"];
		[empty setProperty:@YES forKey:@"enabled"];
		[self insertSpecifier:empty atIndex:1];
		return;
	}

	// Newest first.
	for(NSInteger i = log.count - 1; i >= 0; i--) {
		PSSpecifier* entry = [PSSpecifier preferenceSpecifierNamed:log[i] target:self set:NULL get:NULL detail:nil cell:PSStaticTextCell edit:nil];
		[entry setProperty:@"SHDWDetectorLogEntry" forKey:@"id"];
		[entry setProperty:@YES forKey:@"enabled"];
		[self insertSpecifier:entry atIndex:1];
	}
}

- (void)clearLog:(id)sender {
	UIAlertController* alert = [UIAlertController alertControllerWithTitle:[self localized:@"CLEAR_CONFIRM_TITLE" fallback:@"Clear Detector Log?"] message:[self localized:@"CLEAR_CONFIRM_MSG" fallback:@"This removes all recorded detector activity. This cannot be undone."] preferredStyle:UIAlertControllerStyleAlert];

	[alert addAction:[UIAlertAction actionWithTitle:[self localized:@"CLEAR_CANCEL" fallback:@"Cancel"] style:UIAlertActionStyleCancel handler:nil]];
	[alert addAction:[UIAlertAction actionWithTitle:[self localized:@"CLEAR_CONFIRM" fallback:@"Clear"] style:UIAlertActionStyleDestructive handler:^(UIAlertAction* action) {
		[prefs removeObjectForKey:@"DetectorLog"];
		[prefs synchronize];
		[self reloadLogEntries];
	}]];

	[self presentViewController:alert animated:YES completion:nil];
}

- (void)shareLog:(id)sender {
	NSArray* log = [prefs arrayForKey:@"DetectorLog"];

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
	}

	return self;
}
@end