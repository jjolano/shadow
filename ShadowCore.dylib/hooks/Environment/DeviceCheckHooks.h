#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <HookKit.h>

// Descriptor-driven ObjC hook table for the DeviceCheck group.
//
// Each row describes one method to neutralize. Installation walks the table
// and, for every row whose class exists and whose method's runtime type
// encoding matches the row's accepted return encoding, swaps in the matching
// replacement IMP via the passed message-capable HKSubstitutor (the same
// instance DeviceCheck.x's shadowhook_DeviceCheck receives). Rows whose
// class/method is absent or whose encoding is not accepted are skipped; a
// skipped row with an UNKNOWN encoding is logged once (fail open — the real
// method is left untouched).
//
// Accepted return encodings:
//   'B'/_Bool, 'c'/'C' (char)  -> BOOL-style scalar replacement (policy
//                                 false/true via DCHPolicy)
//   '@' (object)               -> object replacement (policy nil)
// Anything else is UNKNOWN -> fail open, log once, skip.
//
// Replacement IMPs are typed to the method shape they serve:
//   DCHReplacementIMP0 - zero-argument method: (id self, SEL _cmd) -> scalar/obj
//   DCHReplacementIMP1 - one-argument  method: (id self, SEL _cmd, id a0) -> scalar
// Table rows select the IMP that matches their argCount.

// Result policy for accepted scalar encodings. (Object-returning rows always
// return nil.)
typedef NS_ENUM(uint8_t, DCHPolicy) {
    DCHPolicyFalse = 0,   // return NO / false / 0
    DCHPolicyTrue  = 1,   // return YES / true / 1
};

// Method kind: class method (+ ...) vs instance method (- ...).
typedef NS_ENUM(uint8_t, DCHMethodKind) {
    DCHMethodInstance = 0,
    DCHMethodClass    = 1,
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

// Typed replacement IMPs (exact function types for each method shape).
// Scalar family (B/c rows): zero-arg and one-arg, per-policy.
static inline BOOL shdw_dch_imp0_bool_false(id self, SEL _cmd) { return NO;  }
static inline BOOL shdw_dch_imp0_bool_true (id self, SEL _cmd) { return YES; }
static inline BOOL shdw_dch_imp1_bool_false(id self, SEL _cmd, id a0) { return NO;  }
static inline BOOL shdw_dch_imp1_bool_true (id self, SEL _cmd, id a0) { return YES; }
// Object family (@ rows): zero-arg only for the two step-1 probes.
static inline id   shdw_dch_imp0_obj_nil  (id self, SEL _cmd) { return nil; }

// Installs every descriptor row whose class exists and whose method's runtime
// encoding matches the row. `hooks` must be a message-capable HKSubstitutor
// (it is passed to HKHookMessage). Returns the number of hooks installed.
NSUInteger shdw_devicecheck_install_hooks(HKSubstitutor* hooks);
