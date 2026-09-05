// Bridging header for the SwiftyJBD runner.
//
// Upstream JailBreak.swift is a bare two-method fragment (no enclosing type,
// no imports). build-detector-harness.sh wraps it into `struct SwiftyJBD` with
// Foundation/UIKit imports; Theos compiles it into this runner's module, so
// the only C symbol Swift needs is the shared runner bridge.
#include "../RunnerSupportC.h"
