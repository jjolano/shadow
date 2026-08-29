/*
 THESIS: A native test ledger makes every SDK verdict scannable without hiding raw evidence.
 OWN-WORLD: Inset-grouped system lists, semantic colors, SF Symbols, and standard navigation.
 STORY: Scan clean/jailbroken states, open one SDK, inspect every check, then rerun it.
 FIRST VIEWPORT: Large title above a dense SDK list; status icon and words lead each row.
 FORM: Native Settings-style master/detail, fixed by the product brief.
 FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, and DESIGN.md
*/

#import "DetectorDashboard.h"
#import "Detectors.h"
#import "StatusViewController.h"

static NSString* const SHDWResultsDirectory = @"/var/mobile/Documents/ShadowDetectorTests";
NSNotificationName const SHDWDetectorResultsChanged = @"SHDWDetectorResultsChanged";

@interface SHDWSDK : NSObject
@property(nonatomic, copy) NSString* identifier;
@property(nonatomic, copy) NSString* name;
@property(nonatomic, copy) NSString* version;
@property(nonatomic, copy) NSString* scheme;
@property(nonatomic, copy) NSString* sourceURL;
@end

@implementation SHDWSDK
@end

static SHDWSDK* SHDWMakeSDK(NSString* identifier, NSString* name, NSString* version, NSString* scheme, NSString* sourceURL) {
    SHDWSDK* sdk = [SHDWSDK new];
    sdk.identifier = identifier;
    sdk.name = name;
    sdk.version = version;
    sdk.scheme = scheme;
    sdk.sourceURL = sourceURL;
    return sdk;
}

static NSArray<SHDWSDK*>* SHDWSDKs(void) {
    static NSArray<SHDWSDK*>* sdks;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sdks = @[
            SHDWMakeSDK(@"dyldprobe", @"dyldprobe", @"1.0.0", @"shadow-dyldprobe://run", @"https://github.com/jjolano/shadow/tree/master/tools/dyldprobe"),
            SHDWMakeSDK(@"iossecuritysuite", @"IOSSecuritySuite", @"2.3.0", @"shadow-detector-iossecuritysuite://run", @"https://github.com/securing/IOSSecuritySuite"),
            SHDWMakeSDK(@"jailbreakdetector", @"JailbreakDetector.swift", @"main@b6afe56", @"shadow-detector-jailbreakdetector://run", @"https://github.com/conmulligan/JailbreakDetector.swift"),
            SHDWMakeSDK(@"securitytoolkit", @"iOS Security Toolkit", @"2.0.0", @"shadow-detector-securitytoolkit://run", @"https://github.com/EXXETA/iOS-Security-Toolkit"),
            SHDWMakeSDK(@"dttjailbreakdetection", @"DTTJailbreakDetection", @"0.2.0+cedd424", @"shadow-detector-dtt://run", @"https://github.com/thii/DTTJailbreakDetection"),
            SHDWMakeSDK(@"freerasp", @"freeRASP", @"7.1.2", @"shadow-detector-freerasp://run", @"https://github.com/talsec/Free-RASP-iOS"),
            SHDWMakeSDK(@"roothider", @"Roothider JailbreakDetector", @"main@5b3d0be", @"shadow-detector-roothider://run", @"https://github.com/roothider/JailbreakDetector"),
            SHDWMakeSDK(@"batjailbreakguard", @"BATJailbreakGuard", @"main@spm", @"shadow-detector-bat://run", @"https://github.com/Basilabt/BATJailbreakGuard"),
            SHDWMakeSDK(@"safetynet", @"SafetyNet", @"main@spm", @"shadow-detector-safetynet://run", @"https://github.com/DipakPanchasara/SafetyNet"),
            SHDWMakeSDK(@"devicesecuritykit", @"DeviceSecurityKit", @"0.40.0-filtered", @"shadow-detector-dsk://run", @"https://github.com/galahador/DeviceSecurityKit"),
            SHDWMakeSDK(@"jailmonkey", @"JailMonkey", @"v2.8.5", @"shadow-detector-jailmonkey://run", @"https://github.com/GantMan/jail-monkey"),
        ];
    });
    return sdks;
}

static NSString* SHDWReportPath(SHDWSDK* sdk) {
    return [SHDWResultsDirectory stringByAppendingPathComponent:
        [sdk.identifier stringByAppendingPathExtension:@"json"]];
}

static NSString* SHDWString(id value) {
    return [value isKindOfClass:[NSString class]] ? value : nil;
}

static NSDictionary* SHDWDictionary(id value) {
    return [value isKindOfClass:[NSDictionary class]] ? value : nil;
}

static NSArray<NSDictionary*>* SHDWDictionaryArray(id value) {
    if(![value isKindOfClass:[NSArray class]]) return @[];
    NSMutableArray<NSDictionary*>* dictionaries = [NSMutableArray new];
    for(id item in value) {
        if([item isKindOfClass:[NSDictionary class]]) [dictionaries addObject:item];
    }
    return dictionaries;
}

static NSString* SHDWTimingText(NSDictionary* report) {
    NSDictionary* timing = SHDWDictionary(report[@"timing"]);
    NSNumber* elapsed = timing[@"elapsed_ns"];
    NSNumber* first = timing[@"first_elapsed_ns"];
    if(![elapsed isKindOfClass:[NSNumber class]]) return @"Not recorded";
    if([first isKindOfClass:[NSNumber class]]) {
        return [NSString stringWithFormat:@"Latest %.2f ms · first %.2f ms",
            elapsed.doubleValue / 1000000.0, first.doubleValue / 1000000.0];
    }
    return [NSString stringWithFormat:@"%.2f ms", elapsed.doubleValue / 1000000.0];
}

static NSDictionary* SHDWReport(SHDWSDK* sdk) {
    NSData* data = [NSData dataWithContentsOfFile:SHDWReportPath(sdk)];
    if(!data) return nil;
    NSError* error = nil;
    id report = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if([report isKindOfClass:[NSDictionary class]]) return report;
    NSString* message = error.localizedDescription ?: @"Report root is not a JSON object";
    return @{
        @"outcome" : @"error",
        @"generatedAt" : @"Unreadable report",
        @"rounds" : @[@{
            @"phase" : @"Report",
            @"checks" : @[@{
                @"id" : @"harness.report",
                @"name" : @"Report JSON",
                @"passed" : @NO,
                @"message" : message,
            }],
        }],
    };
}

static NSString* SHDWOutcome(NSDictionary* report) {
    if(!report) return @"notRun";
    NSString* value = SHDWString(report[@"outcome"]);
    return [value isEqualToString:@"clean"] || [value isEqualToString:@"jailbroken"] ||
        [value isEqualToString:@"error"] || [value isEqualToString:@"running"] ? value : @"error";
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

static NSMutableDictionary<NSString*, NSDictionary*>* SHDWActiveRuns(void) {
    static NSMutableDictionary<NSString*, NSDictionary*>* runs;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ runs = [NSMutableDictionary new]; });
    return runs;
}

static NSDate* SHDWReportDate(SHDWSDK* sdk) {
    return [[NSFileManager defaultManager] attributesOfItemAtPath:SHDWReportPath(sdk)
        error:nil][NSFileModificationDate];
}

static void SHDWBeginRun(SHDWSDK* sdk) {
    SHDWActiveRuns()[sdk.identifier] = @{
        @"started" : [NSDate date],
        @"baseline" : SHDWReportDate(sdk) ?: [NSNull null],
    };
}

static void SHDWEndRun(SHDWSDK* sdk) {
    [SHDWActiveRuns() removeObjectForKey:sdk.identifier];
}

static BOOL SHDWRunActive(SHDWSDK* sdk) {
    NSDictionary* state = SHDWActiveRuns()[sdk.identifier];
    if(!state) return NO;

    NSDate* started = state[@"started"];
    if(-started.timeIntervalSinceNow > 60) {
        SHDWEndRun(sdk);
        return NO;
    }

    NSDate* baseline = [state[@"baseline"] isKindOfClass:[NSDate class]] ? state[@"baseline"] : nil;
    NSDate* current = SHDWReportDate(sdk);
    if(current && (!baseline || [current compare:baseline] == NSOrderedDescending) &&
       ![SHDWOutcome(SHDWReport(sdk)) isEqualToString:@"running"]) {
        SHDWEndRun(sdk);
        return NO;
    }

    return YES;
}

static UIActivityIndicatorView* SHDWSpinner(void) {
    UIActivityIndicatorView* spinner = [[UIActivityIndicatorView alloc]
        initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    [spinner startAnimating];
    return spinner;
}

@interface SHDWSDKDetailController : UITableViewController
- (instancetype)initWithSDK:(SHDWSDK*)sdk;
@end

@implementation SHDWSDKDetailController {
    SHDWSDK* _sdk;
    NSDictionary* _report;
    NSArray<NSDictionary*>* _rounds;
    NSTimer* _refreshTimer;
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
    [_refreshTimer invalidate];
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self refresh];
}

- (void)refresh {
    _report = SHDWReport(_sdk);
    _rounds = SHDWDictionaryArray(_report[@"rounds"]);
    BOOL running = SHDWRunActive(_sdk);
    self.navigationItem.rightBarButtonItem.title = running ? @"Running" : @"Run";
    self.navigationItem.rightBarButtonItem.enabled = !running;
    if(running && !_refreshTimer) {
        _refreshTimer = [NSTimer scheduledTimerWithTimeInterval:0.5 target:self
            selector:@selector(refreshTimer:) userInfo:nil repeats:YES];
    } else if(!running && _refreshTimer) {
        [_refreshTimer invalidate];
        _refreshTimer = nil;
    }
    [self.tableView reloadData];
}

- (void)refreshTimer:(NSTimer*)timer {
    (void)timer;
    [self refresh];
}

- (void)runSDK {
    SHDWBeginRun(_sdk);
    [[NSNotificationCenter defaultCenter] postNotificationName:SHDWDetectorResultsChanged object:nil];
    dispatch_async(dispatch_get_main_queue(), ^{
        BOOL ok = SHDWRunDetectorWithID(self->_sdk.identifier);
        SHDWEndRun(self->_sdk);
        [[NSNotificationCenter defaultCenter] postNotificationName:SHDWDetectorResultsChanged object:nil];
        if(!ok){
            UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Detector unavailable"
                message:[NSString stringWithFormat:@"No in-process detector for %@.", self->_sdk.identifier]
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        }
    });
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView {
    return 1 + MAX((NSInteger)_rounds.count, 1);
}

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section {
    if(section == 0) return 5;
    if(_rounds.count == 0) return 1;
    NSArray* checks = SHDWDictionaryArray(_rounds[section - 1][@"checks"]);
    return MAX((NSInteger)checks.count, 1);
}

- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section {
    if(section == 0) return @"Summary";
    if(_rounds.count == 0) return @"Results";
    NSString* phase = SHDWString(_rounds[section - 1][@"phase"]);
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
    cell.accessoryView = nil;
    cell.accessoryType = UITableViewCellAccessoryNone;
    cell.accessibilityTraits = UIAccessibilityTraitNone;
    cell.accessibilityValue = nil;
    cell.accessibilityHint = nil;

    if(indexPath.section == 0) {
        BOOL running = SHDWRunActive(_sdk);
        NSString* outcome = running ? @"running" : SHDWOutcome(_report);
        if(indexPath.row == 0) {
            cell.textLabel.text = @"Status";
            cell.detailTextLabel.text = SHDWOutcomeTitle(outcome);
            if(running) {
                cell.imageView.image = nil;
                cell.accessoryView = SHDWSpinner();
            } else {
                cell.imageView.image = [UIImage systemImageNamed:SHDWOutcomeSymbol(outcome)];
                cell.imageView.tintColor = SHDWOutcomeColor(outcome);
            }
            cell.accessibilityValue = SHDWOutcomeTitle(outcome);
        } else if(indexPath.row == 1) {
            cell.textLabel.text = @"Runner version";
            cell.detailTextLabel.text = SHDWString(SHDWDictionary(_report[@"sdk"])[@"version"]) ?: _sdk.version;
        } else if(indexPath.row == 2) {
            cell.textLabel.text = @"Last run";
            cell.detailTextLabel.text = SHDWString(_report[@"generatedAt"]) ?: @"Never";
        } else if(indexPath.row == 3) {
            cell.textLabel.text = @"Detector time";
            cell.detailTextLabel.text = SHDWTimingText(_report);
            cell.accessibilityValue = cell.detailTextLabel.text;
        } else {
            cell.textLabel.text = @"Source repository";
            cell.detailTextLabel.text = _sdk.sourceURL;
            cell.imageView.image = [UIImage systemImageNamed:@"link"];
            cell.imageView.tintColor = UIColor.systemBlueColor;
            cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
            cell.accessibilityTraits = UIAccessibilityTraitLink;
            cell.accessibilityValue = _sdk.sourceURL;
            cell.accessibilityHint = @"Opens the detector's source repository.";
        }
        return cell;
    }

    if(_rounds.count == 0) {
        cell.textLabel.text = @"No result yet";
        cell.detailTextLabel.text = @"Tap Run to execute the in-process detector.";
        cell.imageView.image = [UIImage systemImageNamed:@"circle"];
        cell.imageView.tintColor = UIColor.systemGrayColor;
        return cell;
    }

    NSArray<NSDictionary*>* checks = SHDWDictionaryArray(_rounds[indexPath.section - 1][@"checks"]);
    if(checks.count == 0) {
        cell.textLabel.text = @"No checks reported";
        cell.detailTextLabel.text = nil;
        return cell;
    }
    NSDictionary* check = checks[indexPath.row];
    BOOL inconclusive = [check[@"inconclusive"] boolValue];
    BOOL passed = [check[@"passed"] boolValue];
    cell.textLabel.text = SHDWString(check[@"name"]) ?: SHDWString(check[@"id"]) ?: @"Check";
    cell.detailTextLabel.text = SHDWString(check[@"message"]) ?: (inconclusive ? @"Inconclusive" : (passed ? @"Passed" : @"Detected"));
    cell.imageView.image = [UIImage systemImageNamed:inconclusive ? @"questionmark.circle.fill" : (passed ? @"checkmark.circle.fill" : @"xmark.circle.fill")];
    cell.imageView.tintColor = inconclusive ? UIColor.systemGrayColor : (passed ? UIColor.systemGreenColor : UIColor.systemRedColor);
    return cell;
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if(indexPath.section != 0 || indexPath.row != 4) return;
    NSURL* url = [NSURL URLWithString:_sdk.sourceURL];
    if(!url) return;
    [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:^(BOOL success) {
        if(success) return;
        dispatch_async(dispatch_get_main_queue(), ^{
            UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Unable to open source"
                message:@"Check the device connection and try again."
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        });
    }];
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
    return section == 0 ? @"Built-in" : @"Bundled detectors";
}

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section {
    if(section == 0) return nil;
    return @"A clean result means the bundled detector reported no jailbreak evidence. Tap a detector for every check and its raw message.";
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath {
    static NSString* const reuse = @"SDK";
    UITableViewCell* cell = [tableView dequeueReusableCellWithIdentifier:reuse];
    if(!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:reuse];
    cell.textLabel.adjustsFontForContentSizeCategory = YES;
    cell.detailTextLabel.adjustsFontForContentSizeCategory = YES;
    cell.accessoryView = nil;
    cell.accessoryType = UITableViewCellAccessoryNone;
    cell.accessibilityValue = nil;

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
    BOOL running = SHDWRunActive(sdk);
    NSString* outcome = running ? @"running" : SHDWOutcome(report);
    cell.textLabel.text = sdk.name;
    cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ · %@", SHDWOutcomeTitle(outcome),
        SHDWString(SHDWDictionary(report[@"sdk"])[@"version"]) ?: sdk.version];
    if(running) {
        cell.imageView.image = nil;
        cell.accessoryView = SHDWSpinner();
    } else {
        cell.imageView.image = [UIImage systemImageNamed:SHDWOutcomeSymbol(outcome)];
        cell.imageView.tintColor = SHDWOutcomeColor(outcome);
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    }
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
