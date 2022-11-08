#import "hooks.h"

%group shadowhook_DeviceCheck
%hook DCDevice
- (BOOL)isSupported {
    // maybe returning unsupported can skip some app attest token generations
	return NO;
}
%end
%end

void shadowhook_DeviceCheck(void) {
    %init(shadowhook_DeviceCheck);
}
