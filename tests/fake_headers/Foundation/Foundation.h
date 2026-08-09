// Host-test stub for Apple's <Foundation/Foundation.h>: lets the test include
// the REAL Headers/HookKit/Compat.h on Linux. Compat.h only uses these names
// in declarations; the test never touches them at runtime.
#ifndef fake_foundation_h
#define fake_foundation_h
typedef unsigned long NSUInteger;
typedef signed char BOOL;
#define NS_ENUM(_type, _name) enum _name : _type _name; enum _name : _type
@interface NSObject @end
@interface NSArray <__covariant ObjectType> @end
@interface NSDictionary <__covariant KeyType, __covariant ObjectType> @end
@interface NSNumber @end
@interface NSValue @end
@interface NSString @end
#endif
