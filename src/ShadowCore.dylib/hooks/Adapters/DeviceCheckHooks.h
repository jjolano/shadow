#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import "../../SHDWHookSession.h"

// Descriptor hook table.

// Result policy for accepted scalar encodings. (Object-returning rows always
// return nil.)
typedef NS_ENUM(uint8_t, DCHPolicy) {
    DCHPolicyFalse = 0,   // return NO / false / 0
    DCHPolicyTrue  = 1,   // return YES / true / 1
};

// Method kind: class (+) vs instance (-) method.
typedef NS_ENUM(uint8_t, DCHMethodKind) {
    DCHMethodInstance = 0,
    DCHMethodClass    = 1,
};

typedef NS_OPTIONS(uint8_t, DCHTarget) {
    DCHTargetNone       = 0,
    DCHTargetDTT        = 1 << 0,
    DCHTargetSafeDevice = 1 << 1,
    DCHTargetJailMonkey = 1 << 2,
};

typedef struct {
    const char* className;   // runtime class name (objc_getClass)
    const char* selector;    // selector name
    DCHMethodKind kind;      // class vs instance method
    char         encoding;   // accepted return encoding: 'B', 'c'/'C', or '@'
    uint8_t      argCount;   // args after self/_cmd: 0 or 1
    DCHPolicy    policy;     // false/true for scalars; ignored for '@'
} DCHDescriptor;

// Table terminator: { NULL, NULL, 0, 0, 0, 0 }.
extern const DCHDescriptor shdw_devicecheck_descriptors[];

// Typed replacement IMPs.
static inline BOOL shdw_dch_imp0_bool_false(id self, SEL _cmd) { return NO;  }
static inline BOOL shdw_dch_imp0_bool_true (id self, SEL _cmd) { return YES; }
static inline BOOL shdw_dch_imp1_bool_false(id self, SEL _cmd, id a0) { return NO;  }
static inline BOOL shdw_dch_imp1_bool_true (id self, SEL _cmd, id a0) { return YES; }
static inline id    shdw_dch_imp0_obj_nil (id self, SEL _cmd) { return nil; }
static inline void* shdw_dch_imp0_ptr_null(id self, SEL _cmd) { return NULL; }

// Installs matching descriptor rows. Returns the number installed.
NSUInteger shdw_devicecheck_install_hooks(SHDWHookSession* hooks, DCHTarget enabledTargets);
