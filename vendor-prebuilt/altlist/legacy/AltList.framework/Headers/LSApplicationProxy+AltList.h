#import <MobileCoreServices/LSApplicationProxy.h>
#import <MobileCoreServices/LSApplicationWorkspace.h>

@interface LSApplicationProxy (AltList)
- (BOOL)atl_isSystemApplication;
- (BOOL)atl_isUserApplication;
- (BOOL)atl_isHidden;
- (NSString*)atl_fastDisplayName;
- (NSString*)atl_nameToDisplay;
@property (nonatomic,readonly) NSString* atl_bundleIdentifier;
@end

@interface LSApplicationWorkspace (AltList)
- (NSArray*)atl_allInstalledApplications;
@end