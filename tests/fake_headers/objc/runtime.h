// Host-test stub for Apple's <objc/runtime.h>: the vendored libsubstitute
// header declares substitute_hook_objc_message under __APPLE__, which needs
// Class/SEL/IMP/bool. The classifier under test never touches these.
#ifndef fake_objc_runtime_h
#define fake_objc_runtime_h
#include <stdbool.h>
typedef struct objc_class *Class;
typedef struct objc_selector *SEL;
typedef void (*IMP)(void);
#endif
