// ponytail: minimal React Native bridge stubs so the REAL JailMonkey.m can
// compile in-process without the RN framework (the RN bridge is how the module
// is exposed to JS apps — irrelevant to the harness).
#import <Foundation/Foundation.h>
typedef void (^RCTPromiseResolveBlock)(id result);
typedef void (^RCTPromiseRejectBlock)(NSString *code, NSString *message, NSError *error);
@protocol RCTBridgeModule
@end
#define RCT_EXPORT_MODULE()
#define RCT_EXPORT_METHOD(method) - (void)method