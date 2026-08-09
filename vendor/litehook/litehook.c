#include "litehook.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <string.h>
#include <sys/fcntl.h>
#include <mach/mach.h>
#include <mach/arm/kern_return.h>
#include <mach/port.h>
#include <mach/vm_prot.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <dlfcn.h>
#include <libkern/OSCacheControl.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld_images.h>
#include <sys/syslimits.h>
#include <dispatch/dispatch.h>
#include <dyld_cache_format.h>
#include <ptrauth.h>
#include <sys/mman.h>

#if __arm64__
#define _COMM_PAGE_START_ADDRESS (0x0000000FFFFFC000ULL)
#define _COMM_PAGE_TPRO_WRITE_ENABLE (_COMM_PAGE_START_ADDRESS + 0x0D0)
#define _COMM_PAGE_TPRO_WRITE_DISABLE (_COMM_PAGE_START_ADDRESS + 0x0D8)

static bool os_tpro_is_supported(void)
{
	if (*(uint64_t*)_COMM_PAGE_TPRO_WRITE_ENABLE) {
		return true;
	}
	return false;
}

__attribute__((naked)) bool os_thread_self_tpro_is_writeable(void)
{
	__asm__ __volatile__ (
		"mrs             x0, s3_6_c15_c1_5\n"
		"ubfx            x0, x0, #0x24, #1;\n"
		"ret\n"
	);
}

void os_thread_self_restrict_tpro_to_rw(void)
{
	__asm__ __volatile__ (
		"mov x0, %0\n"
		"ldr x0, [x0]\n"
		"msr s3_6_c15_c1_5, x0\n"
		"isb sy\n"
		:: "r" (_COMM_PAGE_TPRO_WRITE_ENABLE)
		: "memory", "x0"
	);
	return;
}

void os_thread_self_restrict_tpro_to_ro(void)
{
	__asm__ __volatile__ (
		"mov x0, %0\n"
		"ldr x0, [x0]\n"
		"msr s3_6_c15_c1_5, x0\n"
		"isb sy\n"
		:: "r" (_COMM_PAGE_TPRO_WRITE_DISABLE)
		: "memory", "x0"
	);
	return;
}
#endif

size_t _lth_fstrlen(FILE *f)
{
	size_t sz = 0;
	uint32_t prev = ftell(f);
	while (true) {
		char c = 0;
		if (fread(&c, sizeof(c), 1, f) != 1) break;
		if (c == 0) break;
		sz++;
	}
	fseek(f, prev, SEEK_SET);
	return sz;
}

uint32_t _lth_arm64_gen_movk(uint8_t x, uint16_t val, uint16_t lsl)
{
	uint32_t base = 0b11110010100000000000000000000000;

	uint32_t hw = 0;
	if (lsl == 16) {
		hw = 0b01 << 21;
	}
	else if (lsl == 32) {
		hw = 0b10 << 21;
	}
	else if (lsl == 48) {
		hw = 0b11 << 21;
	}

	uint32_t imm16 = (uint32_t)val << 5;
	uint32_t rd = x & 0x1F;

	return base | hw | imm16 | rd;
}

uint32_t _lth_arm64_gen_br(uint8_t x)
{
	uint32_t base = 0b11010110000111110000000000000000;
	uint32_t rn = ((uint32_t)x & 0x1F) << 5;
	return base | rn;
}

__attribute__((noinline, naked)) volatile kern_return_t litehook_vm_protect(mach_port_name_t target, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)
{
#ifdef __arm64__
	__asm("mov x16, #-14");
	__asm("svc 0x80");
	__asm("ret");
#else
	// broken....
	__asm("mov r12, #-14");
	__asm("svc 0x80");
	__asm("bx lr");
#endif
}

kern_return_t litehook_unprotect(vm_address_t addr, vm_size_t size)
{
	return litehook_vm_protect(mach_task_self(), addr, size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
}

// Simple memcpy reimplementation since we can't have any external dependencies during critical section
static void litehook_memcpy(void *target, void *source, size_t size)
{
	uint8_t *targetBytes = target;
	uint8_t *sourceBytes = source;
	for (size_t i = 0; i < size; i++) {
		targetBytes[i] = sourceBytes[i];
	}
}

kern_return_t litehook_hook_memory_default(void *target, void *source, size_t sourceSize)
{
	// Read the protection of the region the patch lands in: restoring a
	// hard-coded RX would strip write access from patched writable
	// (__DATA-style) targets, and guessing is worse than failing. If the
	// region cannot be queried, or the patch range crosses into a neighbour
	// region (whose protection would be a guess), reject the patch.
	vm_address_t regionAddr = (vm_address_t)target;
	vm_size_t regionSize = 0;
	vm_region_basic_info_data_64_t info;
	mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t objectName = MACH_PORT_NULL;
	kern_return_t kr = vm_region_64(mach_task_self(), &regionAddr, &regionSize,
			VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &infoCount, &objectName);
	if (kr != KERN_SUCCESS) {
		if (objectName) mach_port_deallocate(mach_task_self(), objectName);
		return kr;
	}
	if (objectName) {
		mach_port_deallocate(mach_task_self(), objectName);
	}

	uint64_t patchStart = (uint64_t)(uintptr_t)target;
	uint64_t patchEnd = patchStart + sourceSize;
	uint64_t regionEnd = (uint64_t)regionAddr + regionSize;
	if (patchStart < (uint64_t)regionAddr || patchEnd > regionEnd || patchEnd < patchStart) {
		// patch crosses the region boundary (or the range wrapped): the
		// neighbour's protection is unknown — reject rather than guess
		return KERN_FAILURE;
	}

	kr = litehook_unprotect((vm_address_t)target, sourceSize);
	if (kr != KERN_SUCCESS) return kr;

	litehook_memcpy(target, source, sourceSize);

	kr = litehook_vm_protect(mach_task_self(), (mach_vm_address_t)target, sourceSize, false, info.protection);
	if (kr != KERN_SUCCESS) return kr;

	sys_icache_invalidate(target, sourceSize);

	return KERN_SUCCESS;
}

kern_return_t (*litehook_hook_memory)(void *target, void *source, size_t sourceSize) = litehook_hook_memory_default;

kern_return_t litehook_hook_function(void *source, void *target)
{
	void *sourceUnsigned = ptrauth_strip(source, ptrauth_key_function_pointer);
	void *targetUnsigned = ptrauth_strip(target, ptrauth_key_function_pointer);

	uint32_t hookBytes[] = {
		_lth_arm64_gen_movk(16, (uint64_t)targetUnsigned >>  0,  0),
		_lth_arm64_gen_movk(16, (uint64_t)targetUnsigned >> 16, 16),
		_lth_arm64_gen_movk(16, (uint64_t)targetUnsigned >> 32, 32),
		_lth_arm64_gen_movk(16, (uint64_t)targetUnsigned >> 48, 48),
		_lth_arm64_gen_br(16),
	};

	return litehook_hook_memory(sourceUnsigned, hookBytes, sizeof(hookBytes));
}

const char *litehook_locate_dsc(void)
{
	static char dscPath[PATH_MAX] = {};
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		char *dyldSharedRegion   = getenv("DYLD_SHARED_REGION");
		char *dyldSharedCacheDir = getenv("DYLD_SHARED_CACHE_DIR");
		if (dyldSharedRegion && dyldSharedCacheDir && !strcmp(dyldSharedRegion, "private")) {
			// If the local process uses a custom private dsc, use that as the path
			strlcpy(dscPath, dyldSharedCacheDir, PATH_MAX);
			strlcat(dscPath, "/dyld_shared_cache", PATH_MAX);
		}
		else if (!access("/System/Library/Caches/com.apple.dyld", F_OK)) /* iOS <=15 */ {
			strlcpy(dscPath, "/System/Library/Caches/com.apple.dyld/dyld_shared_cache", PATH_MAX);
		}
		else if (!access("/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld", F_OK)) /* iOS >=16 */ {
			strlcpy(dscPath, "/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache", PATH_MAX);
		}

		const char *suffixCandidates[] = {
			"_arm64e",
			"_arm64",
			"_armv7s",
			"_armv7",
		};
		char *rChar = &dscPath[strlen(dscPath)];
		for (int i = 0; i < sizeof(suffixCandidates)/sizeof(*suffixCandidates); i++) {
			*rChar = '\0';
			strlcat(dscPath, suffixCandidates[i], PATH_MAX);
			if (!access(dscPath, F_OK)) {
				break;
			}
		}
		if (access(dscPath, F_OK) != 0) strlcpy(dscPath, "", PATH_MAX);
	});
	return (const char *)dscPath;
}

uintptr_t litehook_get_dsc_slide(void)
{
	static uintptr_t slide = 0;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		task_dyld_info_data_t dyldInfo;
		uint32_t count = TASK_DYLD_INFO_COUNT;
		task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
		struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyldInfo.all_image_info_addr;
		slide = infos->sharedCacheSlide;
	});
	return slide;
}

bool is_pointer_to_instructions(const mach_header_u *header, uintptr_t ptr)
{
	const struct load_command *lc =
		(const struct load_command *)((const uint8_t *)header + sizeof(struct mach_header_64));

	for (uint32_t i = 0; i < header->ncmds; i++) {
		if (lc->cmd == LC_SEGMENT_64) {
			const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
			const struct section_64 *sect =
				(const struct section_64 *)((const uint8_t *)seg + sizeof(struct segment_command_64));

			for (uint32_t s = 0; s < seg->nsects; s++, sect++) {
				uint64_t sectStart = (uintptr_t)header + sect->addr;
				uint64_t sectEnd   = sectStart + sect->size;

				if ((ptr >= sect->addr) && (ptr < sectEnd)) {
					uint32_t attrs = sect->flags & SECTION_ATTRIBUTES_USR;
					return (attrs & S_ATTR_PURE_INSTRUCTIONS) ||
						   (attrs & S_ATTR_SOME_INSTRUCTIONS);
				}
			}
		}
		lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
	}

	return false;
}

void *_litehook_sign_if_executable(void *ptr, const mach_header_u *optHeader)
{
	const mach_header_u *header = optHeader;
	if (!header) {
		Dl_info info;
		if (!dladdr(ptr, &info)) { 
			return ptr;
		}
		header = (const mach_header_u *)info.dli_fbase;
	}
	if (!is_pointer_to_instructions(header, (uintptr_t)ptr)) {
		return ptr;
	}
	return ptrauth_sign_unauthenticated(ptr, ptrauth_key_function_pointer, 0);
}

void *litehook_find_symbol(const mach_header_u *header, const char *symbolName)
{
	struct symtab_command *symtabCommand = NULL;
	segment_command_u *linkeditSegCommand = NULL;

	uint32_t slide = -1;

	uint32_t off = 0;
	for (uint32_t i = 0; i < header->ncmds && off < header->sizeofcmds; i++) {
		struct load_command *lc = (struct load_command *)((uintptr_t)header + sizeof(mach_header_u) + off);

		if (lc->cmd == LC_SYMTAB) {
			symtabCommand = (struct symtab_command *)lc;
		}
		else if (lc->cmd == LC_SEGMENT_U) {
			segment_command_u *segCmd = (segment_command_u *)lc;
			if (slide == -1) {
				slide = (uintptr_t)header - segCmd->vmaddr;
			}
			if (!strncmp(segCmd->segname, "__LINKEDIT", sizeof(segCmd->segname))) {
				linkeditSegCommand = segCmd;
			}
		}

		if (symtabCommand && linkeditSegCommand) break;

		off += lc->cmdsize;
	}

	if (!symtabCommand || !linkeditSegCommand) return NULL;

	uint8_t *linkedit = (uint8_t *)((uintptr_t)header + linkeditSegCommand->vmaddr);

	nlist_u *syms = (nlist_u *)(linkedit + (symtabCommand->symoff - linkeditSegCommand->fileoff));
	char *strtbl = (char *)(linkedit + (symtabCommand->stroff - linkeditSegCommand->fileoff));
	size_t strtblSize = symtabCommand->strsize;

	for (uint32_t i = 0; i < symtabCommand->nsyms; i++) {
		nlist_u *symEntry = &syms[i];

		uint32_t stroff = symEntry->n_un.n_strx;
		if (stroff >= strtblSize || off == 0) {
			continue;
		}

		if ((symEntry->n_type & N_TYPE) != N_SECT) {
			continue;
		}

		const char* curSymbolName = &strtbl[stroff];
		if (curSymbolName[0] == '\x00') {
			continue;
		}

		if (!strcmp(curSymbolName, symbolName)) {
			return _litehook_sign_if_executable((void *)((uintptr_t)header + symEntry->n_value), header);
		}
	}

	return NULL;
}

void *litehook_find_dsc_symbol(const char *imagePath, const char *symbolName)
{
	const char *mainDSCPath = litehook_locate_dsc();
	if (!strlen(mainDSCPath)) return NULL;

	char symbolDSCPath[PATH_MAX];
	strcpy(symbolDSCPath, mainDSCPath);
	strcat(symbolDSCPath, ".symbols");

	void *symbol = NULL;

	FILE *mainDSC = fopen(mainDSCPath, "rb");
	if (!mainDSC) goto end;
	FILE *symbolDSC = fopen(symbolDSCPath, "rb") ?: mainDSC;

	int imageIndex = -1;

	struct dyld_cache_header mainHeader;
	if (fread(&mainHeader, sizeof(mainHeader), 1, mainDSC) != 1) goto end;

	for (int i = 0; i < mainHeader.imagesCount; i++) {
		struct dyld_cache_image_info imageInfo;
		fseek(mainDSC, mainHeader.imagesOffset + sizeof(imageInfo) * i, SEEK_SET);
		if (fread(&imageInfo, sizeof(imageInfo), 1, mainDSC) != 1) goto end;

		char path[PATH_MAX];
		fseek(mainDSC, imageInfo.pathFileOffset, SEEK_SET);
		if (fread(path, PATH_MAX, 1, mainDSC) != 1) goto end;

		if (!strcmp(path, imagePath)) {
			imageIndex = i;
			break;
		}
	}

	struct dyld_cache_header symbolHeader;
	if (fread(&symbolHeader, sizeof(symbolHeader), 1, symbolDSC) != 1) goto end;

	struct dyld_cache_local_symbols_info symbolInfo;
	fseek(symbolDSC, symbolHeader.localSymbolsOffset, SEEK_SET);
	if (fread(&symbolInfo, sizeof(symbolInfo), 1, symbolDSC) != 1) goto end;

	if (imageIndex >= symbolInfo.entriesCount) goto end;

	struct dyld_cache_local_symbols_entry_64 entry;

	if (mainHeader.mappingOffset >= offsetof(struct dyld_cache_header, symbolFileUUID)) {
		// New shared cache, dyld_cache_local_symbols_entry_64
		fseek(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.entriesOffset + (sizeof(entry) * imageIndex), SEEK_SET);
		if (fread(&entry, sizeof(entry), 1, symbolDSC) != 1) goto end;
	}
	else {
		// Old shared cache, dyld_cache_local_symbols_entry
		struct dyld_cache_local_symbols_entry entryOld;
		fseek(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.entriesOffset + (sizeof(entryOld) * imageIndex), SEEK_SET);
		if (fread(&entryOld, sizeof(entryOld), 1, symbolDSC) != 1) goto end;

		// Convert dyld_cache_local_symbols_entry to dyld_cache_local_symbols_entry_64
		entry = (struct dyld_cache_local_symbols_entry_64) {
			.dylibOffset = entryOld.dylibOffset,
			.nlistStartIndex = entryOld.nlistStartIndex,
			.nlistCount = entryOld.nlistCount,
		};
	}

	if ((entry.nlistStartIndex + entry.nlistCount) > symbolInfo.nlistCount) goto end;

	for (uint32_t i = entry.nlistStartIndex; i < entry.nlistStartIndex + entry.nlistCount; i++) {
		struct nlist_64 n;
		fseek(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.nlistOffset + (sizeof(n) * i), SEEK_SET);
		if (fread(&n, sizeof(n), 1, symbolDSC) != 1) goto end;

		fseek(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.stringsOffset + n.n_un.n_strx, SEEK_SET);
		size_t len = _lth_fstrlen(symbolDSC);
		char curSymbolName[len+1];
		if (fread(curSymbolName, len+1, 1, symbolDSC) != 1) goto end;
		if (!strcmp(curSymbolName, symbolName)) {
			symbol = _litehook_sign_if_executable((void *)(litehook_get_dsc_slide() + n.n_value), NULL);
		}
	}

end:
	if (mainDSC) {
		if (symbolDSC != mainDSC) {
			fclose(symbolDSC);
		}
		fclose(mainDSC);
	}

	return symbol;
}

// Tally of GOT slots rewritten by the most recent litehook_rebind_symbol
// call, so callers can tell a real rebind from a silent no-op. Captured under
// the same lock as the apply and handed back through the call's out-param.
// Reset on each public call; accumulated by every per-header application it
// triggers (including dyld add-image callback walks).
static size_t gRebindMatches = 0;

// Serializes gRebinds mutations (realloc + append in litehook_rebind_symbol)
// against the dyld add-image callback walk (_litehook_apply_global_rebinds),
// which dyld can fire on any thread mid-dlopen. Both sides lock, and neither
// path re-enters the lock, so a plain mutex suffices (the recursive static
// initializer is feature-macro-guarded out of pthread.h in this build).
// Also guards the match tally, which the apply paths touch.
// ponytail: one global lock, fine at HookKit's hook-setup scale; split per
// rebind if throughput ever matters.
static pthread_mutex_t gRebindLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t gRebindRegisterOnce = PTHREAD_ONCE_INIT;

// The add-image callback walk is defined below the registration function, so
// declare it here for the reference in _litehook_register_global_rebind_callback.
void _litehook_apply_global_rebinds(const mach_header_u *mh, intptr_t vmaddr_slide);

// The add-image callback walks the rebind list; registered exactly once via
// pthread_once (see litehook_rebind_symbol). Registration must NOT run while
// holding gRebindLock: _dyld_register_func_for_add_image invokes the callback
// synchronously for already-loaded images, and the callback takes the lock.
static void _litehook_register_global_rebind_callback(void)
{
	_dyld_register_func_for_add_image((void (*)(const struct mach_header *, intptr_t))_litehook_apply_global_rebinds);
}

void _litehook_rebind_symbol_in_section(const mach_header_u *targetHeader, section_u *section, void *replacee, void *replacement)
{
	char segname[sizeof(section->segname)+1];
	strlcpy(segname, section->segname, sizeof(segname));
	char sectname[sizeof(section->sectname)+1];
	strlcpy(sectname, section->sectname, sizeof(sectname));

	unsigned long sectionSize = 0;
	uint8_t *sectionStart = getsectiondata(targetHeader, segname, sectname, &sectionSize);

	bool auth = !strcmp(sectname, "__auth_got");

	void **symbolPointers = (void **)sectionStart;
	replacee = ptrauth_strip(ptrauth_auth_function(replacee, ptrauth_key_function_pointer, 0), ptrauth_key_function_pointer);

	for (uint32_t i = 0; i < (sectionSize / sizeof(void *)); i++) {
		void *symbolPointer = symbolPointers[i];
		if (!symbolPointer) continue;

		if (auth) symbolPointer = ptrauth_strip(ptrauth_auth_function(symbolPointers[i], ptrauth_key_function_pointer, &symbolPointers[i]), ptrauth_key_function_pointer);

		if (symbolPointer == replacee) {
#if __arm64__
			bool needsTPRORevert = false;
			if (os_tpro_is_supported()) {
				if (!os_thread_self_tpro_is_writeable()) {
					os_thread_self_restrict_tpro_to_rw();
					needsTPRORevert = true;
				}
			}
#endif
			litehook_unprotect((vm_address_t)&symbolPointers[i], sizeof(void *));
			if (auth) { 
				symbolPointers[i] = ptrauth_auth_and_resign(replacement, ptrauth_key_function_pointer, 0, ptrauth_key_process_independent_code, &symbolPointers[i]);
			}
			else {
				symbolPointers[i] = ptrauth_strip(replacement, ptrauth_key_function_pointer);
			}
#if __arm64__
			if (needsTPRORevert) {
				os_thread_self_restrict_tpro_to_ro();
			}
#endif
			gRebindMatches++;
		}
	}
}

typedef struct {
	const mach_header_u *sourceHeader;
	void *replacee;
	void *replacement;
	bool (*exceptionFilter)(const mach_header_u *header);
} global_rebind;

uint32_t gRebindCount = 0;
global_rebind *gRebinds = NULL;

// Per-header rebind core, shared by the public single-header path and the
// global path's per-image application. No counter reset here: the caller
// (litehook_rebind_symbol) owns the tally window so a global rebind totals
// every image it touches.
static void _litehook_rebind_header(const mach_header_u *targetHeader, void *replacee, void *replacement, bool (*exceptionFilter)(const mach_header_u *header))
{
	struct load_command *lcp = (void *)((uintptr_t)targetHeader + sizeof(mach_header_u));
	for(int i = 0; i < targetHeader->ncmds; i++) {
		if (lcp->cmd == LC_SEGMENT_U) {
			segment_command_u *segCmd = (segment_command_u *)lcp;
			if (!strncmp(segCmd->segname, "__AUTH_CONST", sizeof(segCmd->segname)) ||
				!strncmp(segCmd->segname, "__DATA_CONST", sizeof(segCmd->segname)) ||
				!strncmp(segCmd->segname, "__DATA", sizeof(segCmd->segname))) {
				section_u *sections = (void *)((uintptr_t)lcp + sizeof(segment_command_u));
				for (int j = 0; j < segCmd->nsects; j++) {
					if ((sections[j].flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS || 
						(sections[j].flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
						_litehook_rebind_symbol_in_section(targetHeader, &sections[j], replacee, replacement);
					}
				}
			}
		}
		lcp = (void *)((uintptr_t)lcp + lcp->cmdsize);
	}
}

void _litehook_apply_global_rebind(const mach_header_u *mh, global_rebind *rebind)
{
	if (mh != rebind->sourceHeader) {
		bool filterAllowed = true;
		if (rebind->exceptionFilter) filterAllowed = rebind->exceptionFilter(mh);
		if (filterAllowed) {
			_litehook_rebind_header(mh, rebind->replacee, rebind->replacement, NULL);
		}
	}
}

void _litehook_apply_global_rebinds(const mach_header_u *mh, intptr_t vmaddr_slide)
{
	// dyld callback: can fire on any thread while another thread mutates the
	// list in litehook_rebind_symbol. Lock BEFORE reading the list state —
	// the early-return probe must live inside the critical section, or the
	// realloc in litehook_rebind_symbol races this reader.
	pthread_mutex_lock(&gRebindLock);

	if (gRebinds && gRebindCount != 0) {
		for (uint32_t i = 0; i < gRebindCount; i++) {
			// Apply all existing rebinds for newly loaded image
			_litehook_apply_global_rebind(mh, &gRebinds[i]);
		}
	}

	pthread_mutex_unlock(&gRebindLock);
}

kern_return_t litehook_rebind_symbol(const mach_header_u *targetHeader, void *replacee, void *replacement, bool (*exceptionFilter)(const mach_header_u *header), unsigned int *outMatchCount)
{
	// Ensure the add-image callback is registered before the first global
	// rebind, OUTSIDE the mutex: registration synchronously fires the
	// callback for already-loaded images, and the callback takes the mutex
	// to walk the list. pthread_once also removes the old retry edge (a
	// realloc failure after registration previously left the list null, and
	// a retry re-registered the callback).
	pthread_once(&gRebindRegisterOnce, _litehook_register_global_rebind_callback);

	pthread_mutex_lock(&gRebindLock);

	// Fresh tally window per public call: the count reflects this invocation
	// (and its per-image applications), nothing earlier.
	gRebindMatches = 0;

	if (outMatchCount) {
		*outMatchCount = 0;
	}

	if (targetHeader == LITEHOOK_REBIND_GLOBAL) {
		if (!replacee || !replacement) {
			pthread_mutex_unlock(&gRebindLock);
			return KERN_INVALID_ARGUMENT;
		}

		// We need the mach_header in which the replacement function lives, since we want to exclude it from the rebind
		Dl_info replacementInfo = {};
		if (dladdr(replacement, &replacementInfo) == 0) {
			pthread_mutex_unlock(&gRebindLock);
			return KERN_FAILURE;
		}
		if (replacementInfo.dli_fname == NULL) {
			pthread_mutex_unlock(&gRebindLock);
			return KERN_FAILURE;
		}
		const mach_header_u *sourceHeader = NULL;
		for (unsigned i = 0; i < _dyld_image_count(); i++) {
			if (!strcmp(_dyld_get_image_name(i), replacementInfo.dli_fname)) {
				sourceHeader = (const mach_header_u *)_dyld_get_image_header(i);
				break;
			}
		}
		if (!sourceHeader) {
			pthread_mutex_unlock(&gRebindLock);
			return KERN_FAILURE;
		}

		// Staged candidate record, filled in but NOT committed to gRebinds
		// yet: the current-image scan below decides whether this rebind has
		// anything to do. The dyld add-image callback walks gRebinds under the
		// same lock, so the candidate can never be observed half-committed.
		// HookKit: upstream litehook appends the global record before scanning,
		// so a zero-match rebind stayed registered and applied to FUTURE image
		// loads — silently contradicting the caller's side-effect-free
		// contract. Committing only on a first match keeps the zero-match path
		// a true no-op (nothing retained, nothing applied later), and is
		// exactly as safe under the lock as the old append-first order.
		global_rebind candidate = {
			.sourceHeader = sourceHeader,
			.replacee = replacee,
			.replacement = replacement,
			.exceptionFilter = exceptionFilter,
		};

		for (uint32_t i = 0; i < _dyld_image_count(); i++) {
			const mach_header_u *header = (const mach_header_u *)_dyld_get_image_header(i);
			// Apply new rebind for all already loaded images
			_litehook_apply_global_rebind(header, &candidate);
		}

		if (gRebindMatches == 0) {
			// Nothing rewrote a slot: the rebind is a silent no-op. Do not
			// register it — a zero-match global rebind must apply to NO image,
			// past or future, so the caller can report a side-effect-free,
			// retryable failure (HK_ERR_NOT_SUPPORTED). The caller reads the
			// match tally below under this same lock, so this stays race-free.
			// HookKit: upstream appended the record regardless of the scan
			// result, leaking the rebind into every future image load.
			pthread_mutex_unlock(&gRebindLock);
			return KERN_SUCCESS;
		}

		// Grow first so a failed realloc leaves the live list untouched.
		global_rebind *grown = realloc(gRebinds, sizeof(global_rebind) * (gRebindCount + 1));
		if (!grown) {
			pthread_mutex_unlock(&gRebindLock);
			return KERN_MEMORY_FAILURE;
		}
		gRebinds = grown;
		gRebindCount++;

		global_rebind *rebind = &gRebinds[gRebindCount-1];
		*rebind = candidate;
	}
	else {
		_litehook_rebind_header(targetHeader, replacee, replacement, exceptionFilter);
	}

	// Capture the tally under the same lock as the apply, so the caller's
	// zero-match decision cannot race a concurrent dyld callback walk.
	if (outMatchCount) {
		*outMatchCount = (unsigned int)gRebindMatches;
	}

	pthread_mutex_unlock(&gRebindLock);
	return KERN_SUCCESS;
}
