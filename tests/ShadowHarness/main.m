#import <UIKit/UIKit.h>

#import <string.h>
#import <unistd.h>

#import "AppDelegate.h"
#import "Detectors.h"
#import "StatusViewController.h"

int main(int argc, char* argv[]) {
	@autoreleasepool {
		BOOL headlessProducer = argc == 2 && strcmp(argv[1], "--shadow-headless-producer") == 0;
		BOOL headlessRunAll = argc == 2 && strcmp(argv[1], "--shadow-headless-run-all") == 0;
		// Injection constructors have completed before main. Emit the machine
		// report here so automation does not depend on scene activation.
		BOOL written = [StatusViewController writeStealthReport];
		if(headlessProducer) {
			if(!written) return 2;
			// Launch-time signals may interrupt pause; keep the exact process
			// alive until the driver's default-disposition SIGTERM cleanup.
			for(;;) pause();
		}
		if(headlessRunAll) return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
		return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
	}
}
