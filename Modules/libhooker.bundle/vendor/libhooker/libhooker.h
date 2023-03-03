//
//  libhooker.h
//  libhooker
//
//  Created by CoolStar on 8/17/19.
//  Copyright © 2019 CoolStar. All rights reserved.
//

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef libhooker_h
#define libhooker_h

#ifdef __cplusplus
extern "C" {
#endif

/*!
* @enum libhooker errors
*
* @abstract
* Get a human readable string for debugging purposes.
*
* @discussion
* Passing zero for the value is useful for when two threads need to reconcile
* the completion of a particular event. Passing a value greater than zero is
* useful for managing a finite pool of resources, where the pool size is equal
* to the value.
*
* @constant LIBHOOKER_OK  No errors took place
* @constant LIBHOOKER_ERR_SELECTOR_NOT_FOUND An Objective-C selector was not found. (This error is from libblackjack)
* @constant LIBHOOKER_ERR_SHORT_FUNC A function was too short to hook
* @constant LIBHOOKER_ERR_BAD_INSN_AT_START A problematic instruction was found at the start. We can't preserve the original function due to this instruction getting clobbered.
* @constant LIBHOOKER_ERR_VM An error took place while handling memory pages
* @constant LIBHOOKER_ERR_NO_SYMBOL No symbol was specified for hooking
*/
enum LIBHOOKER_ERR {
    LIBHOOKER_OK = 0,
    LIBHOOKER_ERR_SELECTOR_NOT_FOUND = 1,
    LIBHOOKER_ERR_SHORT_FUNC = 2,
    LIBHOOKER_ERR_BAD_INSN_AT_START = 3,
    LIBHOOKER_ERR_VM = 4,
    LIBHOOKER_ERR_NO_SYMBOL = 5
};

/*!
* @function LHStrError
*
* @abstract
* Get a human readable string for debugging purposes.
*
* @discussion
* Passing zero for the value is useful for when two threads need to reconcile
* the completion of a particular event. Passing a value greater than zero is
* useful for managing a finite pool of resources, where the pool size is equal
* to the value.
*
* @param err
* The raw error value.
*
* @result
* A human-readable error string, or "Unknown Error" on invalid error.
*/
const char *LHStrError(enum LIBHOOKER_ERR err);

/*!
* @function LHOpenImage
*
* @abstract
* Open a dylib for use with LHFindSymbols
*
* @discussion
* dyld handles do not provide enough information to grab symbols. Use this to have libhooker load the dylib.
*
* @param path
* The path to the image on disk or in the shared cache.
*
* @result
* A handle to the dylib that may then be used with LHFindSymbols to find symbols.
*/
struct libhooker_image *LHOpenImage(const char *path);

/*!
* @function LHCloseImage
*
* @abstract
* Close and free a dylib handle opened with LHOpenImage
*
* @param libhookerImage
* The libhooker handle to the image on disk or in the shared cache.
*/
void LHCloseImage(struct libhooker_image *libhookerImage);

/*!
* @function LHFindSymbols
*
* @abstract
* Search for symbols within a dylib either on disk or in the dyld shared cache.
*
* @discussion
* dyld often is not able to find symbols that are present but not marked as public and/or exported.
* Also often the dyld shared cache has symbols replaced with `<redacted>` when loaded into memory.
*
* @param libhookerImage
* The libhooker handle to the image on disk or in the shared cache
*
* @param symbolNames
* An array of the symbol names to search for
*
* @param searchSyms
* An array that gets populated with the symbols found
*
* @param searchSymCount
* The number of symbols to search for
*
* @result
* Returns true if all symbols were found
*/
bool LHFindSymbols(struct libhooker_image *libhookerImage,
                  const char **symbolNames,
                  void **searchSyms,
                  size_t searchSymCount);

/*!
* @function LHExecMemory
*
* @abstract
* Creates an executable page from raw instruction data
*
* @discussion
* Sometimes a library may generate or load new code, but may simply want an executable page with this new code.
*
* @param page
* A pointer that gets written to with the address of code in the new memory page
*
* @param data
* An array of ARM64 opcodes to write to this new memory page.
*
* @param size
* The size of data
*
* @result
* Returns true if the memory was created. Returns false otherwise.
*/
bool LHExecMemory(void **page, void *data, size_t size);

/*!
* @struct LHMemoryPatch
*
* @abstract
* Describes a memory region to patch
*
* @field destination
* A pointer to the memory location to patch
*
* @field data
* A pointer to the data to write at the patch location
*
* @field size
* The number of bytes to write at the patch location
*
* @field options
* A pointer to an extended options struct. Currently unused.
*
*/
struct LHMemoryPatch {
    void *destination;
    const void *data;
    size_t size;
    void *options;
};

/*!
* @function LHPatchMemory
*
* @abstract
* Patch memory (that may often be read-only or read/execute-only)
*
* @discussion
* Sometimes low level memory access is required to hook parts of applications. This function
* provides an easy way for libraries to do so, with a relatively safe guarantee of preserving
* memory permissions, and re-mapping the memory if required.
*
* @param patches
* A pointer to the destination to write to
*
* @param count
* The number of memory regions to patch
*
* @result
* Returns the number of memory regions successfully patched. This should match count if all regions were succesfully patched.
*
* @result errno
* Returns any errors that may have taken place while hooking the functions
*/
int LHPatchMemory(const struct LHMemoryPatch *patches, int count);

enum LHOptions {
    LHOptionsNone = 0,
    LHOptionsSetJumpReg = 1
};

struct LHFunctionHookOptions {
    enum LHOptions options;
    int jmp_reg;
};

/*!
* @struct LHFunctionhook
*
* @abstract
* Describes a function hook
*
* @field function
* A pointer to the function to hook
*
* @field replacement
* A pointer to the replacement function that will get called in place
*
* @field oldptr
* If not null, this pointer gets written to with the address of a trampoline that lets you call the original function
*
* @discussion
* Setting oldptr to null will allow libhooker to hook smaller functions and will skip over several checks since it does not need to try preserving the original function
*
* @field options
* An optional field that may be populated with a pointer to an LHFunctionHookOptions struct
*/
struct LHFunctionHook {
    void *function;
    void *replacement;
    void *oldptr;
    struct LHFunctionHookOptions *options;
};

/*!
* @function LHHookFunctions
*
* @abstract
* Hook Functions in memory
*
* @discussion
* Libraries often need to hook functions in memory. This provides an easy way to hook the function and get back
* a pointer to the original function, should you need to call it.
*
* @param hooks
* An array of LHFunctionHook describing each function to hook
*
* @param count
* The number of functions to hook
*
* @result
* Returns the number of functions successfully hooked. This should match count if all functions were succesfully hooked.
*
* @result errno
* Returns any errors that may have taken place while hooking the functions
*/
int LHHookFunctions(const struct LHFunctionHook *hooks, int count);

#ifdef __cplusplus
}
#endif

#endif /* libhooker_h */
