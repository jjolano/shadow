#ifndef shdw_hook_adapter_bridge_h
#define shdw_hook_adapter_bridge_h

#import <Foundation/Foundation.h>

@class SHDWHookSession;

typedef NS_OPTIONS(NSUInteger, SHDWUniversalFeatures) {
    SHDWUniversalFeatureImageRebinding = 1 << 0,
    SHDWUniversalFeatureFilesystemMetadata = 1 << 1,
    SHDWUniversalFeatureSymbolicLinks = 1 << 2,
    SHDWUniversalFeatureLaunchServicesURLFiltering = 1 << 3,
};

typedef BOOL (*SHDWAdapterPathPredicate)(NSString* path);
typedef const void* (*SHDWDladdrRemapper)(const void* address, const void* caller);
typedef void (*SHDWUniversalFeatureInstaller)(SHDWHookSession* hooks, const void* imageHeader);

void SHDWSetAdapterPathPredicate(SHDWAdapterPathPredicate predicate);
BOOL SHDWAdapterPathIsHidden(NSString* path);

void SHDWSetDladdrRemapper(SHDWDladdrRemapper remapper);
const void* SHDWRemapDladdrAddress(const void* address, const void* caller);

void SHDWPublishCanOpenURLArtifacts(void* original, void* replacement);
void* SHDWCanOpenURLOriginal(void);
void* SHDWCanOpenURLReplacement(void);

void SHDWRegisterUniversalFeatureInstaller(SHDWUniversalFeatures feature,
                                           SHDWUniversalFeatureInstaller installer);
void SHDWRequestUniversalFeatures(SHDWUniversalFeatures features,
                                  SHDWHookSession* hooks,
                                  const void* imageHeader);

#endif
