#import <UIKit/UIKit.h>

@interface StatusViewController : UIViewController

// Full diagnostics dump (battery section included) as plain text.
- (NSString *)diagnosticsString;

@end
