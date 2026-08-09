#import <HookKit/Compat.h>
#import "Internal/HKBackendInternal.h"
#import "Internal/HKInlineGuard.h"

#import <objc/runtime.h>

#import "native/hk_swift.h"

// Owned here (resolved by swift_available() via dlsym); consumed by the
// engine's name-based lookup (declared in native/hk_swift.h).
hk_swift_demangle_fn hk_swift_demangle = NULL;

// Inline-ownership guard scope: a backend is an inline writer when its hook
// overwrites the target's prologue bytes. native/Dobby/Frida/ElleKit/
// Substrate/Substitute always do for function hooks; litehook only in
// HKStrategyInline mode — its default rebind path is GOT/import-scoped and
// its memory path is a byte blob, neither of which touches the prologue, so
// both stay unguarded. fishhook (rebind) and the Swift backend (vtable
// metadata) are never inline writers either.
static BOOL hk_backend_is_inline_writer(id<HKSubstitutorBackend> backend) {
    if(!backend) {
        return NO;
    }

    // The registry table is the single source of truth for the fixed backends.
    size_t count = 0;
    const HKBackendDescriptor *table = hk_backends(&count);

    for(size_t i = 0; i < count; i++) {
        if(![backend isKindOfClass:table[i].backendClass]) {
            continue;
        }

        switch(table[i].type) {
            case HK_LIB_NATIVE:
            case HK_LIB_DOBBY:
            case HK_LIB_FRIDA:
            case HK_LIB_ELLEKIT:
            case HK_LIB_SUBSTRATE:
            case HK_LIB_SUBSTITUTE:
                return YES;

            case HK_LIB_LITEHOOK:
                // Inline only when the active technique says so: rebind and
                // memory never write the prologue.
                return [backend respondsToSelector:@selector(strategy)] && [(id)backend strategy] == HKStrategyInline;

            default:
                return NO;
        }
    }

    return NO;
}

#pragma mark - HKSubstitutor

@interface HKSubstitutor ()
- (void)noteHookResult:(hookkit_status_t)status fromBackend:(id<HKSubstitutorBackend>)resultBackend;
- (hookkit_lib_t)backendType;
- (BOOL)enqueueKind:(HKHookKind)kind status:(hookkit_status_t *)outStatus build:(void (^)(HKHookOperation *hook))build;
@end

@implementation HKSubstitutor {
    id<HKSubstitutorBackend> backend;
    NSMutableArray<HKHookOperation *> *batchHooks;
    int lastLibErrno;
    hookkit_lib_t lastLibErrnoType;
    // Priority-ordered list of hookkit_lib_t (NSNumber), from substitutorWithOrderedTypes:.
    // Overrides the fixed table priority when non-nil; non-nil-but-empty means no backend.
    NSArray<NSNumber *> *orderedTypes;
    // Priority-ordered list of hookkit_cat_t (NSNumber), from
    // substitutorWithOrderedCategories: (substitutorWithCategory: feeds a
    // single-element list). Tried in order; the first category that resolves
    // to an available backend wins. Non-nil-but-empty means no backend.
    NSArray<NSNumber *> *orderedCategories;
    // Auto-cover routing mode: same shape as orderedCategories, but the
    // backend is chosen PER-HOOK by preflight instead of once at init. The
    // category's pickers are walked in priority order; the first available
    // backend whose side-effect-free preflight accepts the target is invoked
    // exactly once. Set via substitutorWithAutoCoverCategories:.
    NSArray<NSNumber *> *autoCoverCategories;
    // Technique the active backend applies: the winning picker's strategy, or
    // HKStrategyDefault when resolution didn't name one. Zero-init default.
    HKStrategy resolvedStrategy;
}

// activeStrategy is resolvedStrategy: set by the resolution branches in
// initLibraries, readonly on the public surface. `types` is backed by its own
// ivar with an explicit setter that freezes configuration after resolution.
@synthesize types, batching, activeType, activeStrategy = resolvedStrategy;

- (void)setTypes:(hookkit_lib_t)value {
    // Configuration is frozen once a backend has been resolved: mutating the
    // request mask afterwards would leave `types` and `activeType` describing
    // different configurations (initLibraries keeps the original backend).
    // Pre-resolution writes still work, so a failed resolution can be retried
    // with a different request before any backend exists.
    if(!backend) {
        types = value;
    }
}

+ (id<HKSubstitutorBackend>)defaultBackend {
    size_t count = 0;
    const HKBackendDescriptor *table = hk_backends(&count);

    for(size_t i = 0; i < count; i++) {
        if(table[i].automatic && table[i].available()) {
            return [table[i].backendClass new];
        }
    }

    return nil;
}

- (instancetype)init {
    if((self = [super init])) {
        batchHooks = [NSMutableArray new];
        backend = nil;
        types = HK_LIB_NONE;
        activeType = HK_LIB_NONE;
        lastLibErrno = 0;
        lastLibErrnoType = HK_LIB_NONE;
    }

    return self;
}

- (void)initLibraries {
    if(backend) {
        // idempotent: never re-resolve mid-flight (e.g. engine switching)
        return;
    }

    if(orderedTypes) {
        // an explicitly-supplied list is honoured as given: empty yields no
        // backend rather than falling through to the automatic pick
        size_t count = 0;
        const HKBackendDescriptor *table = hk_backends(&count);

        types = HK_LIB_NONE;
        resolvedStrategy = HKStrategyDefault;

        for(NSNumber *num in orderedTypes) {
            for(size_t i = 0; i < count; i++) {
                if(table[i].type == (hookkit_lib_t)num.unsignedIntegerValue && table[i].available()) {
                    backend = [table[i].backendClass new];
                    types |= table[i].type;
                    break;
                }
            }

            if(backend) {
                break;
            }
        }
    } else if(orderedCategories) {
        // Category fallback list: try each category's (backend, strategy)
        // pickers in order; the first category with an available backend wins
        // (its own picker priority decides which). Availability is checked
        // directly (not the automatic flag), so opt-in backends like Native
        // and Frida are still reachable when they are the only option in a
        // category.
        size_t count = 0;
        const HKBackendDescriptor *table = hk_backends(&count);

        types = HK_LIB_NONE;

        for(NSNumber *num in orderedCategories) {
            hookkit_cat_t want = (hookkit_cat_t)num.unsignedIntegerValue;

            if(!want) {
                // HK_CAT_NONE entry: nothing to resolve, keep looking
                continue;
            }

            for(size_t c = 0; c < hk_category_priority_count; c++) {
                if(hk_category_priorities[c].category & want) {
                    for(size_t o = 0; o < hk_category_priorities[c].count; o++) {
                        HKCategoryPicker picker = hk_category_priorities[c].order[o];

                        for(size_t i = 0; i < count; i++) {
                            if(table[i].type == picker.type && table[i].available()) {
                                backend = [table[i].backendClass new];

                                if([backend respondsToSelector:@selector(setStrategy:)]) {
                                    [backend setStrategy:picker.strategy];
                                }

                                resolvedStrategy = picker.strategy;
                                types |= table[i].type;
                                goto category_done;
                            }
                        }
                    }
                }
            }
        }

category_done: ;
    } else if(autoCoverCategories) {
        // Auto-cover mode: no single backend is authoritative. Pin the first
        // available category backend as the fallback used by the batched path
        // and the image APIs; non-batched function hooks route per-hook via
        // preflight instead (see hk_backendForAutoCoverFunction:).
        size_t count = 0;
        const HKBackendDescriptor *table = hk_backends(&count);

        types = HK_LIB_NONE;
        resolvedStrategy = HKStrategyDefault;

        for(NSNumber *num in autoCoverCategories) {
            hookkit_cat_t want = (hookkit_cat_t)num.unsignedIntegerValue;

            if(!want) {
                continue;
            }

            for(size_t c = 0; c < hk_category_priority_count; c++) {
                if(hk_category_priorities[c].category & want) {
                    for(size_t o = 0; o < hk_category_priorities[c].count; o++) {
                        HKCategoryPicker picker = hk_category_priorities[c].order[o];

                        for(size_t i = 0; i < count; i++) {
                            if(table[i].type == picker.type && table[i].available()) {
                                backend = [table[i].backendClass new];

                                if([backend respondsToSelector:@selector(setStrategy:)]) {
                                    [backend setStrategy:picker.strategy];
                                }

                                resolvedStrategy = picker.strategy;
                                types |= table[i].type;
                                goto auto_cover_done;
                            }
                        }
                    }
                }
            }
        }

auto_cover_done: ;
    } else if(types == HK_LIB_NONE) {
        backend = [[self class] defaultBackend];
        resolvedStrategy = HKStrategyDefault;
    } else {
        size_t count = 0;
        const HKBackendDescriptor *table = hk_backends(&count);

        resolvedStrategy = HKStrategyDefault;

        for(size_t i = 0; i < count; i++) {
            if((types & table[i].type) && table[i].available()) {
                backend = [table[i].backendClass new];
                break;
            }
        }
    }
    // explicit types with none available: backend stays nil — the request is
    // honest; the consumer guards with getAvailableSubstitutorTypes

    if(backend) {
        activeType = [self backendType];
    } else {
        activeType = HK_LIB_NONE;
    }
}

- (hookkit_lib_t)typeForBackend:(id<HKSubstitutorBackend>)candidate {
    size_t count = 0;
    const HKBackendDescriptor *table = hk_backends(&count);

    for(size_t i = 0; i < count; i++) {
        if([candidate isKindOfClass:table[i].backendClass]) {
            return table[i].type;
        }
    }

    return HK_LIB_NONE;
}

- (hookkit_lib_t)backendType {
    return [self typeForBackend:backend];
}

- (void)noteHookResult:(hookkit_status_t)status {
    // Default attribution: the pinned backend. The auto-cover path passes the
    // routed backend explicitly (see hookFunction:), since routing can pick a
    // different backend than the one pinned at init.
    [self noteHookResult:status fromBackend:backend];
}

- (void)noteHookResult:(hookkit_status_t)status fromBackend:(id<HKSubstitutorBackend>)resultBackend {
    if(status == HK_OK || status == HK_ERR_INVALID_ARGUMENT) {
        // success, or a caller error with no backend-specific detail
        lastLibErrno = 0;
        lastLibErrnoType = HK_LIB_NONE;
    } else if(resultBackend) {
        int backendErrno = [resultBackend lastErrno];

        if(status == HK_ERR_NOT_SUPPORTED && !([resultBackend isKindOfClass:[HKSwiftBackend class]] && backendErrno != 0)) {
            // Generic capability gate: the backend set no meaningful detail,
            // so clear any stale value from an earlier, unrelated call. The
            // Swift backend is the carve-out — it deliberately maps real
            // engine failures (not-a-Swift-class, no vtable, unsupported
            // layout, ...; see HKNativeBackends.m mapEngineError:) onto
            // NOT_SUPPORTED WITH a meaningful errno, and that detail is
            // preserved like the plain error branch.
            lastLibErrno = 0;
            lastLibErrnoType = HK_LIB_NONE;
        } else {
            lastLibErrno = backendErrno;
            lastLibErrnoType = [self typeForBackend:resultBackend];
        }
    } else {
        lastLibErrno = 0;
        lastLibErrnoType = HK_LIB_NONE;
    }
}

+ (hookkit_lib_t)getAvailableSubstitutorTypes {
    hookkit_lib_t types = HK_LIB_NONE;
    size_t count = 0;
    const HKBackendDescriptor *table = hk_backends(&count);

    for(size_t i = 0; i < count; i++) {
        // Introspection must not ACTIVATE engines: the four dlopen-based
        // backends (ElleKit, Substrate, Substitute, Frida) are probed with
        // their preflight-only discoverable() variants — dlopen_preflight
        // never maps the image and never runs its constructors, so this
        // entry point can no longer initialize a hooking provider. The
        // remaining backends (fishhook/litehook/native/dobby/swift) are
        // compile-time or in-process engine checks with no dlopen, so their
        // available() probes stay as-is. Selection paths (initLibraries,
        // defaultBackend, ...) keep using the full available() probes.
        BOOL available = table[i].available();

        switch(table[i].type) {
            case HK_LIB_ELLEKIT:
                available = libhooker_discoverable();
                break;

            case HK_LIB_SUBSTRATE:
                available = substrate_discoverable();
                break;

            case HK_LIB_SUBSTITUTE:
                available = substitute_discoverable();
                break;

            case HK_LIB_FRIDA:
                available = frida_discoverable();
                break;

            default:
                break;
        }

        if(available) {
            types |= table[i].type;
        }
    }

    return types;
}

+ (hookkit_cat_t)getAvailableCategories {
    hookkit_cat_t cats = HK_CAT_NONE;
    size_t count = 0;
    const HKBackendDescriptor *table = hk_backends(&count);

    // hk_category_priorities is the single source of truth for category
    // membership: a category is available when any of its pickers maps to an
    // available backend — the same lookup initLibraries performs. Same
    // discovery-vs-activation rule as getAvailableSubstitutorTypes: the four
    // dlopen-based backends are probed preflight-only (discoverable(), never
    // loading the engine), the compile-time/in-process backends keep their
    // available() probes.
    for(size_t c = 0; c < hk_category_priority_count; c++) {
        for(size_t o = 0; o < hk_category_priorities[c].count; o++) {
            for(size_t i = 0; i < count; i++) {
                if(table[i].type != hk_category_priorities[c].order[o].type) {
                    continue;
                }

                BOOL available = table[i].available();

                switch(table[i].type) {
                    case HK_LIB_ELLEKIT:
                        available = libhooker_discoverable();
                        break;

                    case HK_LIB_SUBSTRATE:
                        available = substrate_discoverable();
                        break;

                    case HK_LIB_SUBSTITUTE:
                        available = substitute_discoverable();
                        break;

                    case HK_LIB_FRIDA:
                        available = frida_discoverable();
                        break;

                    default:
                        break;
                }

                if(available) {
                    cats |= hk_category_priorities[c].category;
                    break;
                }
            }
        }
    }

    return cats;
}

+ (NSArray<NSDictionary *> *)getSubstitutorTypeInfo:(hookkit_lib_t)types {
    NSMutableArray *result = [NSMutableArray new];
    size_t count = 0;
    const HKBackendDescriptor *table = hk_backends(&count);

    for(size_t i = 0; i < count; i++) {
        if((types & table[i].type) && table[i].available()) {
            [result addObject:@{
                @"id" : table[i].identifier,
                @"name" : table[i].name,
                @"type" : @(table[i].type),
                @"selectable" : @(table[i].selectable)
            }];
        }
    }

    return [result copy];
}

+ (instancetype)substitutorWithTypes:(hookkit_lib_t)types {
    HKSubstitutor *substitutor = [self new];
    [substitutor setTypes:types];
    [substitutor initLibraries];
    return substitutor;
}

+ (instancetype)substitutorWithOrderedTypes:(NSArray<NSNumber *> *)types {
    HKSubstitutor *substitutor = [self new];
    // nil is still an explicit ordered request: treat it as empty, never as unset
    substitutor->orderedTypes = [types copy] ?: @[];
    [substitutor initLibraries];
    return substitutor;
}

+ (instancetype)substitutorWithCategory:(hookkit_cat_t)category {
    // single-element fallback list: shares the ordered resolution loop
    return [self substitutorWithOrderedCategories:@[@(category)]];
}

+ (instancetype)substitutorWithOrderedCategories:(NSArray<NSNumber *> *)categories {
    HKSubstitutor *substitutor = [self new];
    // nil is still an explicit ordered request: treat it as empty, never as unset
    substitutor->orderedCategories = [categories copy] ?: @[];
    [substitutor initLibraries];
    return substitutor;
}

+ (instancetype)substitutorWithAutoCoverCategories:(NSArray<NSNumber *> *)categories {
    HKSubstitutor *substitutor = [self new];
    // nil is still an explicit request: treat it as empty, never as unset
    substitutor->autoCoverCategories = [categories copy] ?: @[];
    // Auto-cover resolves per-hook, so no backend is pinned at init.
    [substitutor initLibraries];
    return substitutor;
}

+ (instancetype)defaultSubstitutor {
    static HKSubstitutor *defaultSubstitutor = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        defaultSubstitutor = [self new];
        [defaultSubstitutor initLibraries];
    });

    return defaultSubstitutor;
}

// Auto-cover routing core: walks the autoCoverCategories list in priority
// order, and within each category walks its picker order. For each
// (category, picker) pair, instantiates the picker's backend and consults its
// side-effect-free preflightFunction: — the first available backend whose
// preflight accepts the target wins. Returns the configured backend, or nil
// when every picker declined (or no category matched).
//
// Deliberately preflight-driven only: it never inspects a hook RESULT to
// decide routing (a failed invocation may have mutated the target). A backend
// without preflightFunction: is presumed to accept (no known veto), matching
// its direct-path behavior.
- (id<HKSubstitutorBackend>)hk_backendForAutoCoverFunction:(void *)function replacement:(void *)replacement {
    size_t count = 0;
    const HKBackendDescriptor *table = hk_backends(&count);

    for(NSNumber *num in autoCoverCategories) {
        hookkit_cat_t want = (hookkit_cat_t)num.unsignedIntegerValue;

        if(!want) {
            continue;
        }

        for(size_t c = 0; c < hk_category_priority_count; c++) {
            if(hk_category_priorities[c].category & want) {
                for(size_t o = 0; o < hk_category_priorities[c].count; o++) {
                    HKCategoryPicker picker = hk_category_priorities[c].order[o];

                    for(size_t i = 0; i < count; i++) {
                        if(table[i].type != picker.type || !table[i].available()) {
                            continue;
                        }

                        id<HKSubstitutorBackend> candidate = [table[i].backendClass new];

                        if([candidate respondsToSelector:@selector(setStrategy:)]) {
                            [candidate setStrategy:picker.strategy];
                        }

                        if(![candidate respondsToSelector:@selector(preflightFunction:withReplacement:)]) {
                            return candidate;   // no veto: accept
                        }

                        hookkit_status_t verdict = [candidate preflightFunction:function withReplacement:replacement];

                        if(verdict == HK_OK) {
                            return candidate;
                        }
                    }
                }
            }
        }
    }

    return nil;
}

// Shared tail of the three batching-capable hook entry points: backend
// presence, the batching decision, the kind check and the enqueue. Returns YES
// when the call is fully handled (result in *outStatus), NO when the caller
// should hook immediately. `build` fills in the kind-specific fields and only
// runs on the enqueue path, so a non-batched hook allocates nothing extra.
//
// The caller's argument guard deliberately stays at the call site, ahead of
// this: hookMemory: copies the patch bytes in `build`, and dataWithBytes:NULL
// would crash before a guard in here could reject it.
- (BOOL)enqueueKind:(HKHookKind)kind status:(hookkit_status_t *)outStatus build:(void (^)(HKHookOperation *hook))build {
    if(!backend) {
        *outStatus = HK_ERR_NOT_SUPPORTED;
    } else if(!batching || ![backend batchingSupported]) {
        return NO;
    } else if(![backend supportsHookKind:kind]) {
        *outStatus = HK_ERR_NOT_SUPPORTED;
    } else {
        HKHookOperation *hook = [HKHookOperation new];
        hook->kind = kind;
        build(hook);

        @synchronized(self) {
            [batchHooks addObject:hook];
        }

        *outStatus = HK_OK;
    }

    [self noteHookResult:*outStatus];
    return YES;
}

- (hookkit_status_t)hookMessageInClass:(Class)objcClass withSelector:(SEL)selector withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    if(!objcClass || !selector || !replacement) {
        [self noteHookResult:HK_ERR_INVALID_ARGUMENT];
        return HK_ERR_INVALID_ARGUMENT;
    }

    // v1-compat: pass the class through to the backend unchanged. Backends
    // resolve their own dispatch — LBHookMessage / MSHookMessageEx /
    // class_replaceMethod all walk the metaclass and superclass chains
    // themselves (class methods hook through the metaclass, inherited
    // instance methods resolve through the class). Normalizing here (e.g.
    // object_getClass() when class_getInstanceMethod() misses) breaks
    // delegate/protocol methods like -applicationDidFinishLaunching: that
    // aren't declared directly on the hook target class — the hook lands on
    // the metaclass, the original IMP is lost, and the real method calls a
    // NULL. v1's modules passed the class through, so this restores that
    // contract. (A selector that exists on neither the class nor the
    // metaclass is left to the backend's own NOT_SUPPORTED check.)
    hookkit_status_t status;

    if([self enqueueKind:HKHookKindMessage status:&status build:^(HKHookOperation *hook) {
        hook->objcClass = objcClass;
        hook->selector = selector;
        hook->replacement = replacement;
        hook->callerOrig = old_ptr;
    }]) {
        return status;
    }

    // owned cell: the backend never touches the caller's pointer directly
    void *cell = NULL;
    hookkit_status_t result = [backend hookMessageInClass:objcClass withSelector:selector withReplacement:replacement outOldPtr:&cell];

    if(result == HK_OK && old_ptr) {
        *old_ptr = cell;
    }

    [self noteHookResult:result];
    return result;
}

- (hookkit_status_t)hookFunction:(void *)function withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    if(!function || !replacement) {
        [self noteHookResult:HK_ERR_INVALID_ARGUMENT];
        return HK_ERR_INVALID_ARGUMENT;
    }

    // Auto-cover routing: pick the first backend whose preflight accepts this
    // target (see hk_backendForAutoCoverFunction:), then invoke it once. When
    // routing is not enabled, `backend` is the pinned resolution.
    id<HKSubstitutorBackend> routeBackend = backend;

    if(autoCoverCategories && !batching) {
        routeBackend = [self hk_backendForAutoCoverFunction:function replacement:replacement];

        if(!routeBackend) {
            // Every picker declined the target: no backend can hook it safely.
            // No backend-specific detail to report — clear any stale state.
            [self noteHookResult:HK_ERR_NOT_SUPPORTED fromBackend:nil];
            return HK_ERR_NOT_SUPPORTED;
        }
    }

    // Process-wide inline-ownership guard: prevents HookKit-vs-HookKit
    // contention — two substitutors (or one hooking twice) installing
    // DIFFERENT inline hooks on the same address through DIFFERENT inline
    // backends would double-patch one prologue. Only inline writers are
    // guarded: rebind paths (fishhook/litehook-rebind) are GOT-scoped and
    // memory patches are byte blobs — neither overwrites the prologue, so
    // both stay unguarded (ponytail: rebind-vs-inline on one address is a
    // same-slot double-write only if the prologue is the GOT slot, which
    // never happens for function pointers).
    uintptr_t guardAddr = 0;

    if(hk_backend_is_inline_writer(routeBackend)) {
        // Normalize the key exactly as the backend will write: strip PAC on
        // arm64e, mask the thumb bit on 32-bit ARM. The same key is stored
        // on the op so executeHooks can update the guard without re-deriving
        // it (ptrauth_strip needs the raw pointer, which the backend may
        // have consumed by then).
#if __has_feature(ptrauth_calls)
        function = ptrauth_strip(function, ptrauth_key_asia);
#endif
#if defined(__arm__)
        uintptr_t addr = (uintptr_t)function & ~(uintptr_t)1;
#else
        uintptr_t addr = (uintptr_t)function;
#endif
        guardAddr = addr;

        void *guardOrig = NULL;
        hk_guard_result_t guard = hk_inline_guard_reserve(addr, replacement, [self typeForBackend:routeBackend], &guardOrig);

        if(guard == HK_GUARD_BLOCKED) {
            // Already inline-hooked by another HookKit backend with a
            // DIFFERENT replacement — invoking this backend would double-
            // patch the prologue. Nothing was written.
            [self noteHookResult:HK_ERR_NOT_SUPPORTED fromBackend:routeBackend];
            return HK_ERR_NOT_SUPPORTED;
        }

        if(guard == HK_GUARD_DUP) {
            // Idempotent same-replacement re-hook: the hook is already
            // installed, so the saved original is the answer.
            if(old_ptr) {
                *old_ptr = guardOrig;
            }

            [self noteHookResult:HK_OK fromBackend:routeBackend];
            return HK_OK;
        }

        // HK_GUARD_OK: entry reserved; the hook proceeds. The entry is
        // settled below (immediate path) or in executeHooks (batched path).
    }

    hookkit_status_t status;

    if([self enqueueKind:HKHookKindFunction status:&status build:^(HKHookOperation *hook) {
        hook->function = function;
        hook->replacement = replacement;
        hook->callerOrig = old_ptr;
        hook->guardAddr = guardAddr;    // 0 = not inline-guarded
    }]) {
        return status;
    }

    // owned cell: the backend never touches the caller's pointer directly
    void *cell = NULL;
    hookkit_status_t result = [routeBackend hookFunction:function withReplacement:replacement outOldPtr:&cell];

    if(guardAddr) {
        // Settle the guard with the actual outcome: OK stores the saved
        // original, HK_ERR taints (the prologue may be half-written), and
        // NOT_SUPPORTED releases the entry (the backend wrote nothing).
        hk_inline_guard_update(guardAddr, result, cell);
    }

    if(result == HK_OK && old_ptr) {
        *old_ptr = cell;
    }

    // Attribute to the backend that actually ran (routeBackend == backend
    // except in auto-cover mode, where routing can pick a different one).
    [self noteHookResult:result fromBackend:routeBackend];
    return result;
}

- (hookkit_status_t)hookMemory:(void *)target withData:(const void *)data size:(size_t)size {
    if(!target || !data || size == 0) {
        [self noteHookResult:HK_ERR_INVALID_ARGUMENT];
        return HK_ERR_INVALID_ARGUMENT;
    }

    hookkit_status_t status;

    if([self enqueueKind:HKHookKindMemory status:&status build:^(HKHookOperation *hook) {
        hook->target = target;
        // copy the patch bytes now: the caller's buffer must not outlive the call
        hook->data = [NSData dataWithBytes:data length:size];
        hook->size = size;
    }]) {
        return status;
    }

    hookkit_status_t result = [backend hookMemory:target withData:data size:size];
    [self noteHookResult:result];
    return result;
}

- (hookkit_status_t)hookSwiftMethodInClass:(Class)objcClass withName:(NSString *)name withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    if(!objcClass || !name || ![name length] || !replacement) {
        [self noteHookResult:HK_ERR_INVALID_ARGUMENT];
        return HK_ERR_INVALID_ARGUMENT;
    }

    if(!backend) {
        [self noteHookResult:HK_ERR_NOT_SUPPORTED];
        return HK_ERR_NOT_SUPPORTED;
    }

    if(![backend respondsToSelector:@selector(hookSwiftMethodInClass:withName:withReplacement:outOldPtr:)]) {
        [self noteHookResult:HK_ERR_NOT_SUPPORTED];
        return HK_ERR_NOT_SUPPORTED;
    }

    // owned cell: the backend never touches the caller's pointer directly
    void *cell = NULL;
    hookkit_status_t result = [backend hookSwiftMethodInClass:objcClass withName:name withReplacement:replacement outOldPtr:&cell];

    if(result == HK_OK && old_ptr) {
        *old_ptr = cell;
    }

    [self noteHookResult:result];
    return result;
}

- (hookkit_status_t)hookSwiftVtableSlotInClass:(Class)objcClass withIndex:(NSUInteger)index withReplacement:(void *)replacement outOldPtr:(void **)old_ptr {
    if(!objcClass || index > UINT32_MAX || !replacement) {
        [self noteHookResult:HK_ERR_INVALID_ARGUMENT];
        return HK_ERR_INVALID_ARGUMENT;
    }

    if(!backend) {
        [self noteHookResult:HK_ERR_NOT_SUPPORTED];
        return HK_ERR_NOT_SUPPORTED;
    }

    if(![backend respondsToSelector:@selector(hookSwiftVtableSlotInClass:withIndex:withReplacement:outOldPtr:)]) {
        [self noteHookResult:HK_ERR_NOT_SUPPORTED];
        return HK_ERR_NOT_SUPPORTED;
    }

    // owned cell: the backend never touches the caller's pointer directly
    void *cell = NULL;
    hookkit_status_t result = [backend hookSwiftVtableSlotInClass:objcClass withIndex:index withReplacement:replacement outOldPtr:&cell];

    if(result == HK_OK && old_ptr) {
        *old_ptr = cell;
    }

    [self noteHookResult:result];
    return result;
}

- (HKImageRef)openImage:(NSString *)path {
    if(!path) {
        return NULL;
    }

    if(!backend) {
        return NULL;
    }

    return [backend openImage:path];
}

- (void)closeImage:(HKImageRef)image {
    if(backend && image) {
        [backend closeImage:image];
    }
}

- (hookkit_status_t)findSymbolsInImage:(HKImageRef)image symbolNames:(NSArray<NSString *> *)symbolNames outSymbols:(NSArray<NSValue *> **)outSymbols {
    if(!symbolNames || ![symbolNames count] || !outSymbols) {
        return HK_ERR_INVALID_ARGUMENT;
    }

    NSMutableArray *outSyms = [NSMutableArray new];
    NSUInteger found = 0;

    for(NSString *symbolName in symbolNames) {
        void *symbol = [self findSymbolInImage:image symbolName:symbolName];

        if(symbol) {
            found += 1;
        }

        [outSyms addObject:[NSValue valueWithPointer:symbol]];
    }

    *outSymbols = [outSyms copy];

    if(found == [symbolNames count]) {
        return HK_OK;
    }

    return found > 0 ? HK_ERR_PARTIAL : HK_ERR;
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    if(!symbolName || ![symbolName length]) {
        return NULL;
    }

    if(!backend) {
        return NULL;
    }

    return [backend findSymbolInImage:image symbolName:symbolName];
}

- (hookkit_status_t)executeHooks {
    NSArray<HKHookOperation *> *hooks;

    @synchronized(self) {
        if(![batchHooks count]) {
            [self noteHookResult:HK_OK];
            return HK_OK;
        }

        hooks = [batchHooks copy];
        [batchHooks removeAllObjects];
    }

    hookkit_status_t result = backend ? [backend executeHooks:hooks] : HK_ERR_NOT_SUPPORTED;

    // copy per-op results back to the callers and drop all borrowed references
    for(HKHookOperation *hook in hooks) {
        // Settle the inline guard for guarded function ops with the batch's
        // per-op outcome. NOT_SUPPORTED never comes out of executeHooks (only
        // the succeeded flag), so taint-on-failure is the honest contract:
        // ponytail: a failed op taints (HK_ERR) rather than releasing — the
        // batch API cannot distinguish "backend wrote nothing" from "backend
        // wrote part of the prologue", so blocking later different hooks is
        // the safe approximation.
        if(hook->guardAddr && hook->kind == HKHookKindFunction) {
            hk_inline_guard_update(hook->guardAddr, hook->succeeded ? 0 : 1, hook->origValue);
        }

        if(hook->callerOrig) {
            if(hook->succeeded) {
                *hook->callerOrig = hook->origValue;
            }

            hook->callerOrig = NULL;
        }
    }

    [self noteHookResult:result];
    return result;
}

- (int)getLibErrno:(hookkit_lib_t *)outType {
    if(outType) {
        *outType = lastLibErrnoType;
    }

    return lastLibErrno;
}
@end