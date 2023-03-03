//
//  libblackjack.h
//  libblackjack
//
//  Created by CoolStar on 2/24/20.
//  Copyright © 2020 CoolStar. All rights reserved.
//

#include "libhooker.h"

#ifndef libblackjack_h
#define libblackjack_h

#ifdef __cplusplus
extern "C" {
#endif

/*!
* @function LBHookMessage
*
* @abstract
* Hook an Objective-C method
*
* @discussion
* Libraries often need to hook Objective-C methods. This provides an easy way to hook the method and call to the
* original method. This also provides a guarantee that hooking a class that doesn't implement a method won't overwrite the method
* in the super class.
*
* @param class
* The Objective C class to hook
*
* @param selector
* The Objective C selector to hook
*
* @param replacement
* A pointer to the replacement implementation that gets called instead of the original function
*
* @param old_ptr
* A pointer to the original implementation that can be called if needed
*
* @result
* Returns any errors that may have taken place when hooking the method
*/
enum LIBHOOKER_ERR LBHookMessage(Class objcClass, SEL selector, void *replacement, void *old_ptr);

#ifdef __cplusplus
}
#endif

#endif /* libblackjack_h */