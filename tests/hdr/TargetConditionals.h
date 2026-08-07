// Minimal stub for Linux builds: dyld_priv.h includes <TargetConditionals.h>
// and consults TARGET_OS_BRIDGE/TARGET_OS_WATCH, which are false on every
// platform this harness runs on. macOS builds use the real one.
#ifndef _TARGETCONDITIONALS_H_
#define _TARGETCONDITIONALS_H_

#define TARGET_OS_MAC 1
#define TARGET_OS_IPHONE 0
#define TARGET_OS_WATCH 0
#define TARGET_OS_BRIDGE 0
#define TARGET_OS_SIMULATOR 0

#endif
