#import <UIKit/UIKit.h>

@interface StatusViewController : UIViewController

// Full diagnostics dump (battery section included) as plain text.
- (NSString *)diagnosticsString;

// Writes Documents/ShadowDiagnostics-<nonce>.json atomically.
+ (BOOL)writeStealthReport;

@end
