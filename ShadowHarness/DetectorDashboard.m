/*
 THESIS: A native test ledger makes every SDK verdict scannable without hiding raw evidence.
 OWN-WORLD: Inset-grouped system lists, semantic colors, SF Symbols, and standard navigation.
 STORY: Scan clean/jailbroken states, open one SDK, inspect every check, then rerun it.
 FIRST VIEWPORT: Large title above a dense SDK list; status icon and words lead each row.
 FORM: Native Settings-style master/detail, fixed by the product brief.
 FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, and DESIGN.md
*/

#import "DetectorDashboard.h"
#import "StatusViewController.h"

static NSString* const SHDWResultsDirectory = @"/var/mobile/Documents/ShadowDetectorTests";
NSNotificationName const SHDWDetectorResultsChanged = @"SHDWDetectorResultsChanged";

@interface SHDWSDK : NSObject
@property(nonatomic, copy) NSString* identifier;
@property(nonatomic, copy) NSString* name;
@property(nonatomic, copy) NSString* version;
@property(nonatomic, copy) NSString* scheme;
@end

@implementation SHDWSDK
@end

static SHDWSDK* SHDWMakeSDK(NSString* identifier, NSString* name, NSString* version, NSString* scheme) {
    SHDWSDK* sdk = [SHDWSDK new];
    sdk.identifier = identifier;
    sdk.name = name;
    sdk.version = version;
    sdk.scheme = scheme;
    return sdk;
}

static NSArray<SHDWSDK*>* SHDWSDKs(void) {
    static NSArray<SHDWSDK*>* sdks;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sdks = @[
            SHDWMakeSDK(@"dyldprobe", @"dyldprobe", @"1.0.0", @"shadow-dyldprobe://run"),
            SHDWMakeSDK(@"iossecuritysuite", @"IOSSecuritySuite", @"2.3.0", @"shadow-detector-iossecuritysuite://run"),
            SHDWMakeSDK(@"dttjailbreakdetection", @"DTTJailbreakDetection", @"0.2.0+cedd424", @"shadow-detector-dtt://run"),
            SHDWMakeSDK(@"freerasp", @"freeRASP", @"6.4.0", @"shadow-detector-freerasp://run"),
        ];
    });
    return sdks;
}

static NSDictionary* SHDWReport(SHDWSDK* sdk) {
    NSString* path = [SHDWResultsDirectory stringByAppendingPathComponent:
        [sdk.identifier stringByAppendingPathExtension:@"json"]];
    NSData* data = [NSData dataWithContentsOfFile:path];
    return data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
}

static NSString* SHDWOutcome(NSDictionary* report) {
    NSString* value = [report[@"outcome"] isKindOfClass:[NSString class]] ? report[@"outcome"] : nil;
    return value ?: @"notRun";
}

static NSString* SHDWOutcomeTitle(NSString* outcome) {
    if([outcome isEqualToString:@"clean"]) return @"Clean";
    if([outcome isEqualToString:@"jailbroken"]) return @"Jailbroken";
    if([outcome isEqualToString:@"error"]) return @"Error";
    if([outcome isEqualToString:@"running"]) return @"Running";
    return @"Not run";
}

static NSString* SHDWOutcomeSymbol(NSString* outcome) {
    if([outcome isEqualToString:@"clean"]) return @"checkmark.circle.fill";
    if([outcome isEqualToString:@"jailbroken"]) return @"xmark.circle.fill";
    if([outcome isEqualToString:@"error"]) return @"exclamationmark.triangle.fill";
    if([outcome isEqualToString:@"running"]) return @"clock.fill";
    return @"circle";
}

static UIColor* SHDWOutcomeColor(NSString* outcome) {
    if([outcome isEqualToString:@"clean"]) return UIColor.systemGreenColor;
    if([outcome isEqualToString:@"jailbroken"]) return UIColor.systemRedColor;
    if([outcome isEqualToString:@"error"]) return UIColor.systemOrangeColor;
    return UIColor.systemGrayColor;
}

@interface SHDWSDKDetailController : UITableViewController
- (instancetype)initWithSDK:(SHDWSDK*)sdk;
@end

@implementation SHDWSDKDetailController {
    SHDWSDK* _sdk;
    NSDictionary* _report;
    NSArray<NSDictionary*>* _rounds;
}

- (instancetype)initWithSDK:(SHDWSDK*)sdk {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if(self) _sdk = sdk;
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = _sdk.name;
    self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeNever;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithTitle:@"Run" style:UIBarButtonItemStylePlain target:self action:@selector(runSDK)];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(refresh)
        name:SHDWDetectorResultsChanged object:nil];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self refresh];
}

- (void)refresh {
    _report = SHDWReport(_sdk);
    _rounds = [_report[@"rounds"] isKindOfClass:[NSArray class]] ? _report[@"rounds"] : @[];
    [self.tableView reloadData];
}

- (void)runSDK {
    NSURL* url = [NSURL URLWithString:_sdk.scheme];
    [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:^(BOOL success) {
        if(success) return;
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Runner unavailable"
            message:@"Reinstall Shadow Harness to restore its isolated runners."
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    }];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView {
    return 1 + MAX((NSInteger)_rounds.count, 1);
}

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section {
    if(section == 0) return 3;
    if(_rounds.count == 0) return 1;
    NSArray* checks = [_rounds[section - 1][@"checks"] isKindOfClass:[NSArray class]]
        ? _rounds[section - 1][@"checks"] : @[];
    return MAX((NSInteger)checks.count, 1);
}

- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section {
    if(section == 0) return @"Summary";
    if(_rounds.count == 0) return @"Results";
    NSString* phase = _rounds[section - 1][@"phase"];
    return phase.length ? [phase capitalizedString] : @"Checks";
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath {
    static NSString* const reuse = @"Detail";
    UITableViewCell* cell = [tableView dequeueReusableCellWithIdentifier:reuse];
    if(!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:reuse];
    cell.textLabel.adjustsFontForContentSizeCategory = YES;
    cell.detailTextLabel.adjustsFontForContentSizeCategory = YES;
    cell.detailTextLabel.numberOfLines = 0;
    cell.imageView.image = nil;
    cell.imageView.tintColor = nil;

    if(indexPath.section == 0) {
        NSString* outcome = SHDWOutcome(_report);
        if(indexPath.row == 0) {
            cell.textLabel.text = @"Status";
            cell.detailTextLabel.text = SHDWOutcomeTitle(outcome);
            cell.imageView.image = [UIImage systemImageNamed:SHDWOutcomeSymbol(outcome)];
            cell.imageView.tintColor = SHDWOutcomeColor(outcome);
        } else if(indexPath.row == 1) {
            cell.textLabel.text = @"Runner version";
            cell.detailTextLabel.text = _report[@"sdk"][@"version"] ?: _sdk.version;
        } else {
            cell.textLabel.text = @"Last run";
            cell.detailTextLabel.text = _report[@"generatedAt"] ?: @"Never";
        }
        return cell;
    }

    if(_rounds.count == 0) {
        cell.textLabel.text = @"No result yet";
        cell.detailTextLabel.text = @"Tap Run to launch the isolated SDK runner.";
        cell.imageView.image = [UIImage systemImageNamed:@"circle"];
        cell.imageView.tintColor = UIColor.systemGrayColor;
        return cell;
    }

    NSArray* checks = _rounds[indexPath.section - 1][@"checks"];
    if(checks.count == 0) {
        cell.textLabel.text = @"No checks reported";
        cell.detailTextLabel.text = nil;
        return cell;
    }
    NSDictionary* check = checks[indexPath.row];
    BOOL passed = [check[@"passed"] boolValue];
    cell.textLabel.text = check[@"name"] ?: check[@"id"] ?: @"Check";
    cell.detailTextLabel.text = check[@"message"] ?: (passed ? @"Passed" : @"Detected");
    cell.imageView.image = [UIImage systemImageNamed:passed ? @"checkmark.circle.fill" : @"xmark.circle.fill"];
    cell.imageView.tintColor = passed ? UIColor.systemGreenColor : UIColor.systemRedColor;
    return cell;
}

@end

@implementation SHDWSDKListController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Shadow Harness";
    self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeAlways;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh target:self action:@selector(refresh:)];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(refresh:)
        name:SHDWDetectorResultsChanged object:nil];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self refresh:nil];
}

- (void)refresh:(id)sender {
    (void)sender;
    [self.tableView reloadData];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView {
    return 2;
}

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section {
    return section == 0 ? 1 : SHDWSDKs().count;
}

- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section {
    return section == 0 ? @"Built-in" : @"Isolated runners";
}

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section {
    if(section == 0) return nil;
    return @"A clean result means the isolated runner reported no jailbreak evidence. Tap a runner for every check and its raw message.";
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath {
    static NSString* const reuse = @"SDK";
    UITableViewCell* cell = [tableView dequeueReusableCellWithIdentifier:reuse];
    if(!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:reuse];
    cell.textLabel.adjustsFontForContentSizeCategory = YES;
    cell.detailTextLabel.adjustsFontForContentSizeCategory = YES;

    if(indexPath.section == 0) {
        cell.textLabel.text = @"Shadow diagnostics";
        cell.detailTextLabel.text = @"Hooks, rules, and stealth probes";
        cell.imageView.image = [UIImage systemImageNamed:@"waveform.path.ecg"];
        cell.imageView.tintColor = UIColor.systemBlueColor;
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        cell.accessibilityValue = @"Live diagnostics";
        return cell;
    }

    SHDWSDK* sdk = SHDWSDKs()[indexPath.row];
    NSDictionary* report = SHDWReport(sdk);
    NSString* outcome = SHDWOutcome(report);
    cell.textLabel.text = sdk.name;
    cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ · %@", SHDWOutcomeTitle(outcome),
        report[@"sdk"][@"version"] ?: sdk.version];
    cell.imageView.image = [UIImage systemImageNamed:SHDWOutcomeSymbol(outcome)];
    cell.imageView.tintColor = SHDWOutcomeColor(outcome);
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    cell.accessibilityValue = SHDWOutcomeTitle(outcome);
    return cell;
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if(indexPath.section == 0) {
        [self.navigationController pushViewController:[StatusViewController new] animated:YES];
        return;
    }
    [self.navigationController pushViewController:
        [[SHDWSDKDetailController alloc] initWithSDK:SHDWSDKs()[indexPath.row]] animated:YES];
}

@end
