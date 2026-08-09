/* -----------------------------------------------------------------*-C-*-
   libffi 3.2.1 - Copyright (c) 2011, 2014 Anthony Green
                    - Copyright (c) 1996-2003, 2007, 2008 Red Hat, Inc.

   Permission is hereby granted, free of charge, to any person
   obtaining a copy of this software and associated documentation
   files (the ``Software''), to deal in the Software without
   restriction, including without limitation the rights to use, copy,
   modify, merge, publish, distribute, sublicense, and/or sell copies
   of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED ``AS IS'', WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
   HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
   WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.

   ----------------------------------------------------------------------- */

/* -------------------------------------------------------------------
   libffi is built based on libffi-3.2.1, provides universal library
   (i386, x86_64, armv7, arm64), both ffi_call and ffi_closure are fully
   tested.
   -------------------------------------------------------------------- */

#ifdef __arm64__
#include <ffi_arm64.h>
#endif

#ifdef __i386__
#include <ffi_i386.h>
#endif

#ifdef __arm__
#include <ffi_arm.h>
#endif

#ifdef __x86_64__
#include <ffi_x86_64.h>
#endif
