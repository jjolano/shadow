#import <UIKit/UIKit.h>

#import <string.h>
#import <unistd.h>

#import "AppDelegate.h"
#import "StatusViewController.h"

int main(int argc, char* argv[]) {
	@autoreleasepool {
		BOOL headless = NO;
		for(int i = 1; i < argc; i++) {
			if(strcmp(argv[i], "--shadow-headless-producer") == 0) {
				headless = YES;
				break;
			}
		}
		// Injection constructors have completed before main. Emit the machine
		// report here so automation does not depend on scene activation.
		BOOL written = [StatusViewController writeStealthReport];
		if(headless) {
			if(!written) return 2;
			// Launch-time signals may interrupt pause; keep the exact process
			// alive until the driver's default-disposition SIGTERM cleanup.
			for(;;) pause();
		}
		return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
	}
}
