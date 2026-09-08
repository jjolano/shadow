#import "SHDWUpdatesController.h"
#import "SHDWPrefs.h"

@implementation SHDWUpdatesController {
	UITableView* table;
	NSString* latestVersion;
	NSString* latestTitle;
	NSString* latestBody;
	NSURL* releaseURL;
	NSDate* lastChecked;
	BOOL releaseFetchFailed;
	BOOL fetchingLatestVersion;
	NSUInteger requestGeneration;
	NSURLSession* releaseSession;
	NSURLSessionDataTask* latestVersionTask;
}

- (NSString *)localized:(NSString *)key {
	return [[NSBundle bundleForClass:[self class]] localizedStringForKey:key value:key table:@"About"];
}

- (void)viewDidLoad {
	[super viewDidLoad];
	self.title = [self localized:@"UPDATES_HDR"];
	table = [[UITableView alloc] initWithFrame:self.view.bounds style:UITableViewStyleGrouped];
	table.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
	table.dataSource = self;
	table.delegate = self;
	table.rowHeight = UITableViewAutomaticDimension;
	table.estimatedRowHeight = 60;
	[self.view addSubview:table];
}

- (void)viewWillAppear:(BOOL)animated {
	[super viewWillAppear:animated];
	[table reloadData];
}

- (void)viewDidDisappear:(BOOL)animated {
	[super viewDidDisappear:animated];
	// Invalidate even on navigation away: NSURLSession retains its delegate.
	++requestGeneration;
	[latestVersionTask cancel];
	[releaseSession invalidateAndCancel];
	latestVersionTask = nil;
	releaseSession = nil;
	fetchingLatestVersion = NO;
}

- (void)checkForUpdates:(id)sender {
	if(fetchingLatestVersion) return;
	fetchingLatestVersion = YES;
	latestVersion = nil;
	latestTitle = nil;
	latestBody = nil;
	releaseURL = nil;
	releaseFetchFailed = NO;
	lastChecked = nil;
	[table reloadData];
	NSUInteger generation = ++requestGeneration;

	// Preserve the release-list selection, excluding artifact-only tags and prereleases.
	NSURL* updateURL = [NSURL URLWithString:@"https://api.github.com/repos/jjolano/shadow/releases?per_page=10"];
	NSURLSessionConfiguration* configuration = [NSURLSessionConfiguration ephemeralSessionConfiguration];
	configuration.timeoutIntervalForRequest = 30;
	configuration.timeoutIntervalForResource = 60;
	configuration.URLCache = nil;
	configuration.HTTPCookieStorage = nil;
	configuration.URLCredentialStorage = nil;
	releaseSession = [NSURLSession sessionWithConfiguration:configuration delegate:self delegateQueue:[NSOperationQueue mainQueue]];
	__weak typeof(self) weakSelf = self;
	latestVersionTask = [releaseSession dataTaskWithURL:updateURL completionHandler:^(NSData* data, NSURLResponse* response, NSError* error) {
		typeof(self) strongSelf = weakSelf;
		if(!strongSelf || generation != strongSelf->requestGeneration) return;

		NSString* version = nil;
		NSString* title = nil;
		NSString* body = nil;
		NSURL* url = nil;
		BOOL failed = YES;

		if(!error && data && [response isKindOfClass:[NSHTTPURLResponse class]] && [(NSHTTPURLResponse *)response statusCode] >= 200 && [(NSHTTPURLResponse *)response statusCode] < 300) {
			id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
			if([json isKindOfClass:[NSArray class]]) {
				failed = NO;
				// The API returns releases newest-first.
				for(id release in (NSArray *)json) {
					if(![release isKindOfClass:[NSDictionary class]] ||
					   ![release[@"prerelease"] isKindOfClass:[NSNumber class]] || [release[@"prerelease"] boolValue]) continue;
					NSString* tag_name = release[@"tag_name"];
					if(![tag_name isKindOfClass:[NSString class]] || tag_name.length == 0) continue;
					NSString* candidate = [tag_name hasPrefix:@"v"] ? [tag_name substringFromIndex:1] : tag_name;
					if([candidate rangeOfString:@"^[0-9]+\\.[0-9]+" options:NSRegularExpressionSearch].location != NSNotFound) {
						version = candidate;
						title = [release[@"name"] isKindOfClass:[NSString class]] ? release[@"name"] : nil;
						if(!title.length) title = tag_name;
						body = [release[@"body"] isKindOfClass:[NSString class]] ? release[@"body"] : nil;
						// Only an unambiguous release page in this repository may be opened.
						NSString* htmlURL = release[@"html_url"];
						if([htmlURL isKindOfClass:[NSString class]]) {
							NSURLComponents* components = [NSURLComponents componentsWithString:htmlURL];
							NSString* prefix = @"/jjolano/shadow/releases/tag/";
							NSString* path = components.percentEncodedPath;
							if([components.scheme isEqualToString:@"https"] && [components.host isEqualToString:@"github.com"] &&
							   !components.port && !components.user && !components.password && !components.query && !components.fragment &&
							   [path hasPrefix:prefix] && [[path substringFromIndex:prefix.length] isEqualToString:tag_name] &&
							   [tag_name rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"/%\\?#"]].location == NSNotFound) {
								url = components.URL;
							}
						}
						break;
					}
				}
			}
		}

		strongSelf->latestVersion = version;
		strongSelf->latestTitle = title;
		strongSelf->latestBody = body;
		strongSelf->releaseURL = url;
		strongSelf->releaseFetchFailed = failed;
		strongSelf->lastChecked = [NSDate date];
		strongSelf->fetchingLatestVersion = NO;
		strongSelf->latestVersionTask = nil;
		[strongSelf->releaseSession finishTasksAndInvalidate];
		strongSelf->releaseSession = nil;
		[strongSelf->table reloadData];
		UIAccessibilityPostNotification(UIAccessibilityLayoutChangedNotification, nil);
	}];
	[latestVersionTask resume];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)request completionHandler:(void (^)(NSURLRequest *))completionHandler {
	completionHandler(nil);
}

- (NSString *)updateStatus {
	if(releaseFetchFailed) return [self localized:@"NOTES_ERROR"];
	if(!latestVersion) return [self localized:@"NOTES_NO_RELEASE"];
	NSString* installed = SHDWInstalledVersion();
	if(!installed) return [self localized:@"UNKNOWN"];
	// ponytail: numeric digit runs cover shipped versions and Debian revisions,
	// not epochs or tilde prereleases; use dpkg ordering if those ever ship.
	BOOL outdated = [installed compare:latestVersion options:NSNumericSearch] == NSOrderedAscending;
	return [self localized:(outdated ? @"UPDATE_AVAILABLE" : @"UP_TO_DATE")];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
	return lastChecked ? (latestVersion ? 3 : 2) : 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
	return section == 0 ? 2 : (section == 1 ? 3 : (releaseURL ? 2 : 1));
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
	return section == 2 ? [self localized:@"RELEASE_NOTES"] : nil;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
	return section == 0 ? [self localized:@"UPDATES_DISCLOSURE"] : nil;
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
	return indexPath.section == 2 && indexPath.row == 0 ? MAX(240, self.view.bounds.size.height * 0.55) : UITableViewAutomaticDimension;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
	UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
	cell.selectionStyle = UITableViewCellSelectionStyleNone;
	cell.textLabel.numberOfLines = 0;
	cell.detailTextLabel.numberOfLines = 0;
	cell.textLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
	cell.detailTextLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleSubheadline];
	for(UILabel* label in @[cell.textLabel, cell.detailTextLabel]) {
		if([label respondsToSelector:@selector(setAdjustsFontForContentSizeCategory:)]) label.adjustsFontForContentSizeCategory = YES;
	}
	BOOL check = indexPath.section == 0 && indexPath.row == 1;
	BOOL external = indexPath.section == 2 && indexPath.row == 1;
	if(check || external) {
		NSString* key = external ? @"VIEW_RELEASE" : (fetchingLatestVersion ? @"UPDATES_CHECKING" :
			(lastChecked ? (releaseFetchFailed || !latestVersion ? @"NOTES_RETRY" : @"CHECK_AGAIN") : @"CHECK_UPDATES"));
		cell.textLabel.text = [self localized:key];
		cell.imageView.image = SHDWSettingsSymbol(external ? @"arrow.up.right.square" : @"arrow.clockwise");
		cell.userInteractionEnabled = !fetchingLatestVersion;
		cell.textLabel.enabled = !fetchingLatestVersion;
		cell.textLabel.textColor = self.view.tintColor;
		cell.selectionStyle = UITableViewCellSelectionStyleDefault;
		cell.accessibilityTraits = UIAccessibilityTraitButton | (fetchingLatestVersion ? UIAccessibilityTraitNotEnabled : 0);
	} else if(indexPath.section == 0) {
		cell.textLabel.text = [self localized:@"INSTALLED_VERSION"];
		cell.detailTextLabel.text = SHDWInstalledVersion() ?: [self localized:@"UNKNOWN"];
	} else if(indexPath.section == 1) {
		cell.textLabel.text = [self localized:@[@"LATEST_VERSION", @"UPDATE_STATUS", @"LAST_CHECKED"][indexPath.row]];
		if(indexPath.row == 0) cell.detailTextLabel.text = latestVersion ?: [self localized:@"UNKNOWN"];
		else if(indexPath.row == 1) cell.detailTextLabel.text = [self updateStatus];
		else cell.detailTextLabel.text = [NSDateFormatter localizedStringFromDate:lastChecked dateStyle:NSDateFormatterMediumStyle timeStyle:NSDateFormatterShortStyle];
	} else {
		cell.isAccessibilityElement = NO;
		UITextView* text = [[UITextView alloc] initWithFrame:cell.contentView.bounds];
		text.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
		text.editable = NO;
		text.selectable = YES;
		text.scrollEnabled = YES;
		text.alwaysBounceVertical = YES;
		text.dataDetectorTypes = UIDataDetectorTypeNone;
		text.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
		text.backgroundColor = [UIColor clearColor];
		text.textColor = [UIColor respondsToSelector:@selector(labelColor)] ? [UIColor labelColor] : [UIColor blackColor];
		if([text respondsToSelector:@selector(setAdjustsFontForContentSizeCategory:)]) text.adjustsFontForContentSizeCategory = YES;
		text.textContainerInset = UIEdgeInsetsMake(12, 16, 12, 16);
		NSString* body = [latestBody stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
		text.text = [NSString stringWithFormat:@"%@\n\n%@", latestTitle, body.length ? latestBody : [self localized:@"NOTES_EMPTY"]];
		[cell.contentView addSubview:text];
	}
	return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
	[tableView deselectRowAtIndexPath:indexPath animated:YES];
	if(indexPath.section == 0 && indexPath.row == 1) [self checkForUpdates:nil];
	else if(indexPath.section == 2 && indexPath.row == 1 && releaseURL && !fetchingLatestVersion) {
		UIApplication* application = [UIApplication sharedApplication];
		if([application respondsToSelector:@selector(openURL:options:completionHandler:)]) {
			[application openURL:releaseURL options:@{} completionHandler:nil];
		} else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
			[application openURL:releaseURL];
#pragma clang diagnostic pop
		}
	}
}

- (void)dealloc {
	[latestVersionTask cancel];
	[releaseSession invalidateAndCancel];
}
@end
