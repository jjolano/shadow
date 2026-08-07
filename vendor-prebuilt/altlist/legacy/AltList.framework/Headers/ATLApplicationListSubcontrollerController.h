#import "ATLApplicationListControllerBase.h"

@interface ATLApplicationListSubcontrollerController : ATLApplicationListControllerBase
@property (nonatomic) Class subcontrollerClass;

- (NSString*)previewStringForApplicationWithIdentifier:(NSString*)applicationID;

@end