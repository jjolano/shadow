#import "SHDWATLController.h"
#import "SHDWPrefs.h"
#import <Shadow/Settings.h>
#import <Preferences/PSTableCell.h>

@implementation SHDWATLController {
	NSUserDefaults* prefs;
}

- (NSString *)previewStringForApplicationWithIdentifier:(NSString *)applicationID {
	return SHDWAppEnabled(prefs, applicationID)
		? [[NSBundle bundleForClass:[self class]] localizedStringForKey:@"ENABLED" value:@"Enabled" table:@"App"]
		: @"";
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
	}

	return self;
}

- (PSTableCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
	PSTableCell* cell = (PSTableCell*)[super tableView:tableView cellForRowAtIndexPath:indexPath];
	NSString* appID = [[cell specifier] propertyForKey:@"applicationIdentifier"];
	cell.accessoryView = nil;
	cell.accessibilityValue = nil;
	if(appID.length && !SHDWAppFollowsGlobal(prefs, appID)) {
		UIStackView* accessory = [[UIStackView alloc] initWithFrame:CGRectMake(0, 0, 42, 24)];
		accessory.axis = UILayoutConstraintAxisHorizontal;
		accessory.alignment = UIStackViewAlignmentCenter;
		accessory.distribution = UIStackViewDistributionEqualSpacing;
		accessory.userInteractionEnabled = NO;
		for(NSString* name in @[@"slider.horizontal.3", @"chevron.right"]) {
			UIImage* image = SHDWSettingsSymbol(name);
			if(image) {
				if([name isEqualToString:@"chevron.right"]) image = [image imageFlippedForRightToLeftLayoutDirection];
				UIImageView* icon = [[UIImageView alloc] initWithImage:image];
				icon.tintColor = cell.tintColor;
				[accessory addArrangedSubview:icon];
			} else {
				UILabel* label = [UILabel new];
				BOOL rtl = [UIView userInterfaceLayoutDirectionForSemanticContentAttribute:cell.semanticContentAttribute] == UIUserInterfaceLayoutDirectionRightToLeft;
				label.text = [name isEqualToString:@"slider.horizontal.3"] ? @"\u2699" : (rtl ? @"<" : @">");
				label.textColor = cell.tintColor;
				[accessory addArrangedSubview:label];
			}
		}
		cell.accessoryView = accessory;
		NSString* customized = [[NSBundle bundleForClass:[self class]] localizedStringForKey:@"CUSTOMIZED" value:nil table:@"App"];
		NSString* preview = [self previewStringForApplicationWithIdentifier:appID];
		NSString* format = [[NSBundle bundleForClass:[self class]] localizedStringForKey:@"APP_STATE_ACCESSIBILITY_FMT" value:nil table:@"App"];
		cell.accessibilityValue = preview.length ? [NSString stringWithFormat:format, preview, customized] : customized;
	}
	return cell;
}

- (void)viewWillAppear:(BOOL)animated {
	[super viewWillAppear:animated];
	[self.table reloadData];
}
@end
