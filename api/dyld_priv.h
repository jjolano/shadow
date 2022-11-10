/* -*- mode: C++; c-basic-offset: 4; tab-width: 4 -*-
 *
 * Copyright (c) 2003-2010 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
#ifndef _MACH_O_DYLD_PRIV_H_
#define _MACH_O_DYLD_PRIV_H_

#include <stdbool.h>
#include <Availability.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>

#if __cplusplus
extern "C" {
#endif /* __cplusplus */



//
// private interface between libSystem.dylib and dyld
//
extern int _dyld_func_lookup(const char* dyld_func_name, void **address);

//
// private interface between libSystem.dylib and dyld
//
extern void _dyld_fork_child();


//
// Possible state changes for which you can register to be notified
//
enum dyld_image_states
{
	dyld_image_state_mapped					= 10,		// No batch notification for this
	dyld_image_state_dependents_mapped		= 20,		// Only batch notification for this
	dyld_image_state_rebased				= 30, 
	dyld_image_state_bound					= 40,
	dyld_image_state_dependents_initialized	= 45,		// Only single notification for this
	dyld_image_state_initialized			= 50,
	dyld_image_state_terminated				= 60		// Only single notification for this
};

// 
// Callback that provides a bottom-up array of images
// For dyld_image_state_[dependents_]mapped state only, returning non-NULL will cause dyld to abort loading all those images
// and append the returned string to its load failure error message. dyld does not free the string, so
// it should be a literal string or a static buffer
//
typedef const char* (*dyld_image_state_change_handler)(enum dyld_image_states state, uint32_t infoCount, const struct dyld_image_info info[]);

//
// Register a handler to be called when any image changes to the requested state.
// If 'batch' is true, the callback is called with an array of all images that are in the requested state sorted by dependency.
// If 'batch' is false, the callback is called with one image at a time as each image transitions to the the requested state.
// During the call to this function, the handler may be called back with existing images and the handler should
// not return a string, since there is no load to abort.  In batch mode, existing images at or past the request
// state supplied in the callback.  In non-batch mode, the callback is called for each image exactly in the
// requested state.    
//
extern void
dyld_register_image_state_change_handler(enum dyld_image_states state, bool batch, dyld_image_state_change_handler handler);


//
// Possible thread-local variable state changes for which you can register to be notified
//
enum dyld_tlv_states {
    dyld_tlv_state_allocated = 10,   // TLV range newly allocated
    dyld_tlv_state_deallocated = 20  // TLV range about to be deallocated
};

// 
// Info about thread-local variable storage.
// 
typedef struct {
    size_t info_size;    // sizeof(dyld_tlv_info)
    void * tlv_addr;     // Base address of TLV storage
    size_t tlv_size;     // Byte size of TLV storage
} dyld_tlv_info;

#if __BLOCKS__

// 
// Callback that notes changes to thread-local variable storage.
// 
typedef void (^dyld_tlv_state_change_handler)(enum dyld_tlv_states state, const dyld_tlv_info *info);

//
// Register a handler to be called when a thread adds or removes storage for thread-local variables.
// The registered handler will only be called from and on behalf of the thread that owns the storage.
// The registered handler will NOT be called for any storage that was 
//   already allocated before dyld_register_tlv_state_change_handler() was 
//   called. Use dyld_enumerate_tlv_storage() to get that information.
// Exists in Mac OS X 10.7 and later 
// 
extern void 
dyld_register_tlv_state_change_handler(enum dyld_tlv_states state, dyld_tlv_state_change_handler handler);

// 
// Enumerate the current thread-local variable storage allocated for the current thread. 
// Exists in Mac OS X 10.7 and later 
//
extern void 
dyld_enumerate_tlv_storage(dyld_tlv_state_change_handler handler);

#endif


//
// get slide for a given loaded mach_header  
// Mac OS X 10.6 and later
//
extern intptr_t _dyld_get_image_slide(const struct mach_header* mh);


//
// get pointer to this process's dyld_all_image_infos
// Exists in Mac OS X 10.4 and later through _dyld_func_lookup()
// Exists in Mac OS X 10.6 and later through libSystem.dylib
//
const struct dyld_all_image_infos* _dyld_get_all_image_infos();



struct dyld_unwind_sections
{
	const struct mach_header*		mh;
	const void*						dwarf_section;
	uintptr_t						dwarf_section_length;
	const void*						compact_unwind_section;
	uintptr_t						compact_unwind_section_length;
};


//
// Returns true iff some loaded mach-o image contains "addr".
//	info->mh							mach header of image containing addr
//  info->dwarf_section					pointer to start of __TEXT/__eh_frame section
//  info->dwarf_section_length			length of __TEXT/__eh_frame section
//  info->compact_unwind_section		pointer to start of __TEXT/__unwind_info section
//  info->compact_unwind_section_length	length of __TEXT/__unwind_info section
//
// Exists in Mac OS X 10.6 and later 
extern bool _dyld_find_unwind_sections(void* addr, struct dyld_unwind_sections* info);


//
// This is an optimized form of dladdr() that only returns the dli_fname field.
//
// Exists in Mac OS X 10.6 and later 
extern const char* dyld_image_path_containing_address(const void* addr);


//
// This is an optimized form of dladdr() that only returns the dli_fbase field.
// Return NULL, if address is not in any image tracked by dyld.
//
// Exists in Mac OS X 10.11 and later
extern const struct mach_header* dyld_image_header_containing_address(const void* addr);



// Convienence constants for return values from dyld_get_sdk_version() and friends.
#define DYLD_MACOSX_VERSION_10_4		0x000A0400
#define DYLD_MACOSX_VERSION_10_5		0x000A0500
#define DYLD_MACOSX_VERSION_10_6		0x000A0600
#define DYLD_MACOSX_VERSION_10_7		0x000A0700
#define DYLD_MACOSX_VERSION_10_8		0x000A0800
#define DYLD_MACOSX_VERSION_10_9		0x000A0900
#define DYLD_MACOSX_VERSION_10_10		0x000A0A00
#define DYLD_MACOSX_VERSION_10_11		0x000A0B00

#define DYLD_IOS_VERSION_2_0		0x00020000
#define DYLD_IOS_VERSION_2_1		0x00020100
#define DYLD_IOS_VERSION_2_2		0x00020200
#define DYLD_IOS_VERSION_3_0		0x00030000
#define DYLD_IOS_VERSION_3_1		0x00030100
#define DYLD_IOS_VERSION_3_2		0x00030200
#define DYLD_IOS_VERSION_4_0		0x00040000
#define DYLD_IOS_VERSION_4_1		0x00040100
#define DYLD_IOS_VERSION_4_2		0x00040200
#define DYLD_IOS_VERSION_4_3		0x00040300
#define DYLD_IOS_VERSION_5_0		0x00050000
#define DYLD_IOS_VERSION_5_1		0x00050100
#define DYLD_IOS_VERSION_6_0		0x00060000
#define DYLD_IOS_VERSION_6_1		0x00060100
#define DYLD_IOS_VERSION_7_0		0x00070000
#define DYLD_IOS_VERSION_7_1		0x00070100
#define DYLD_IOS_VERSION_8_0		0x00080000
#define DYLD_IOS_VERSION_8_1		0x00080100
#define DYLD_IOS_VERSION_8_2		0x00080200
#define DYLD_IOS_VERSION_9_0		0x00090000


//
// This finds the SDK version a binary was built against.
// Returns zero on error, or if SDK version could not be determined.
//
// Exists in Mac OS X 10.8 and later 
// Exists in iOS 6.0 and later
extern uint32_t dyld_get_sdk_version(const struct mach_header* mh);


//
// This finds the SDK version that the main executable was built against.
// Returns zero on error, or if SDK version could not be determined.
//
// Note on WatchOS, this returns the equivalent iOS SDK version number
// (i.e an app built against WatchOS 2.0 SDK returne 9.0).  To see the
// platform specific sdk version use dyld_get_program_sdk_watch_os_version().
//
// Exists in Mac OS X 10.8 and later 
// Exists in iOS 6.0 and later
extern uint32_t dyld_get_program_sdk_version();


// Watch OS only.
// This finds the Watch OS SDK version that the main executable was built against.
// Exists in Watch OS 2.0 and later
extern uint32_t dyld_get_program_sdk_watch_os_version(); // __WATCHOS_AVAILABLE(2.0);


//
// This finds the min OS version a binary was built to run on.
// Returns zero on error, or if no min OS recorded in binary.
//
// Exists in Mac OS X 10.8 and later 
// Exists in iOS 6.0 and later
extern uint32_t dyld_get_min_os_version(const struct mach_header* mh);


//
// This finds the min OS version the main executable was built to run on.
// Returns zero on error, or if no min OS recorded in binary.
//
// Exists in Mac OS X 10.8 and later 
// Exists in iOS 6.0 and later
extern uint32_t dyld_get_program_min_os_version();




//
// Returns if any OS dylib has overridden its copy in the shared cache
//
// Exists in iPhoneOS 3.1 and later 
// Exists in Mac OS X 10.10 and later
extern bool dyld_shared_cache_some_image_overridden();


	
//
// Returns if the process is setuid or is code signed with entitlements.
//
// Exists in Mac OS X 10.9 and later
extern bool dyld_process_is_restricted();



//
// Returns path used by dyld for standard dyld shared cache file for the current arch.
//
// Exists in Mac OS X 10.11 and later
extern const char* dyld_shared_cache_file_path();



//
// <rdar://problem/13820686> for OpenGL to tell dyld it is ok to deallocate a memory based image when done.
//
// Exists in Mac OS X 10.9 and later
#define NSLINKMODULE_OPTION_CAN_UNLOAD                  0x20


//
// Update all bindings on specified image. 
// Looks for uses of 'replacement' and changes it to 'replacee'.
// NOTE: this is less safe than using static interposing via DYLD_INSERT_LIBRARIES
// because the running program may have already copy the pointer values to other
// locations that dyld does not know about.
//
struct dyld_interpose_tuple {
	const void* replacement;
	const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh, const struct dyld_interpose_tuple array[], size_t count);



#if __cplusplus
}
#endif /* __cplusplus */

#endif /* _MACH_O_DYLD_PRIV_H_ */
