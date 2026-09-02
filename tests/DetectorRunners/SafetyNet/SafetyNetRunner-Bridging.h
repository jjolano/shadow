// Bridging header for the SafetyNet runner.
//
// Upstream SafetyNet is an SPM package whose Swift sources `import
// SafetyNetObjC` (a separate C target). Theos compiles every file into one
// module, so that module does not exist here; build-detector-harness.sh strips
// the `import SafetyNetObjC` lines and this header exposes the two C symbols
// the Swift detectors need (safetynet_install_anti_debug, csops) plus the
// shared runner C bridge.
#include "../RunnerSupportC.h"
#include "SafetyNetObjC.h"
