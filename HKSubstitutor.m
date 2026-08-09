#import <HookKit/Compat.h>
#import "Internal/HKBackendInternal.h"

#import <objc/runtime.h>

#import "native/hk_swift.h"

// Owned here (resolved by swift_available() via dlsym); consumed by the
// engine's name-based lookup (declared in native/hk_swift.h).
hk_swift_demangle_fn hk_swift_demangle = NULL;

#pragma mark - HKSubstitutor

@interface HKSubstitutor ()
- (void)noteHookResult:(hookkit_status_t)status;
- (hookkit_lib_t)backendType;
- (BOOL)enqueueKind:(HKHookKind)kind status:(hookkit_status_t *)outStatus build:(void (^)(HKHookOperation *hook))build;
- (void)setAutoCoverCategories:(NSArray<NSNumber *> *)categories;
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
// initLibraries, readonly on the public surface.
@synthesize types, batching, activeType, activeStrategy = resolvedStrategy;

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

- (hookkit_lib_t)backendType {
    size_t count = 0;
    const HKBackendDescriptor *table = hk_backends(&count);

    for(size_t i = 0; i < count; i++) {
        if([backend isKindOfClass:table[i].backendClass]) {
            return table[i].type;
        }
    }

    return HK_LIB_NONE;
}

- (void)noteHookResult:(hookkit_status_t)status {
    if(status == HK_OK || status == HK_ERR_INVALID_ARGUMENT) {
        // success, or a caller error with no backend-specific detail
        lastLibErrno = 0;
        lastLibErrnoType = HK_LIB_NONE;
    } else if(backend) {
        int backendErrno = [backend lastErrno];

        if(status == HK_ERR_NOT_SUPPORTED && !([backend isKindOfClass:[HKSwiftBackend class]] && backendErrno != 0)) {
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
            lastLibErrnoType = activeType;
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
        if(table[i].available()) {
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
    // available backend — the same lookup initLibraries performs.
    for(size_t c = 0; c < hk_category_priority_count; c++) {
        for(size_t o = 0; o < hk_category_priorities[c].count; o++) {
            for(size_t i = 0; i < count; i++) {
                if(table[i].type == hk_category_priorities[c].order[o].type && table[i].available()) {
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

- (void)setAutoCoverCategories:(NSArray<NSNumber *> *)categories {
    // Mutating after init is not supported: resolution already happened.
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

    // Normalize the dispatch class: class methods live on the metaclass, so a
    // class-method-only selector must be hooked through object_getClass() —
    // backends use class_getInstanceMethod(), which walks the metaclass's
    // inheritance tree exactly like the class's own. Instance methods pass the
    // class through unchanged. (A selector that exists on neither the class
    // nor the metaclass is left to the backend's own NOT_SUPPORTED check.)
    Class dispatchClass = class_getInstanceMethod(objcClass, selector) ? objcClass : object_getClass(objcClass);

    hookkit_status_t status;

    if([self enqueueKind:HKHookKindMessage status:&status build:^(HKHookOperation *hook) {
        hook->objcClass = dispatchClass;
        hook->selector = selector;
        hook->replacement = replacement;
        hook->callerOrig = old_ptr;
    }]) {
        return status;
    }

    // owned cell: the backend never touches the caller's pointer directly
    void *cell = NULL;
    hookkit_status_t result = [backend hookMessageInClass:dispatchClass withSelector:selector withReplacement:replacement outOldPtr:&cell];

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
            [self noteHookResult:HK_ERR_NOT_SUPPORTED];
            return HK_ERR_NOT_SUPPORTED;
        }
    }

    hookkit_status_t status;

    if([self enqueueKind:HKHookKindFunction status:&status build:^(HKHookOperation *hook) {
        hook->function = function;
        hook->replacement = replacement;
        hook->callerOrig = old_ptr;
    }]) {
        return status;
    }

    // owned cell: the backend never touches the caller's pointer directly
    void *cell = NULL;
    hookkit_status_t result = [routeBackend hookFunction:function withReplacement:replacement outOldPtr:&cell];

    if(result == HK_OK && old_ptr) {
        *old_ptr = cell;
    }

    [self noteHookResult:result];
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