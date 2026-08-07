#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, ApplicationSectionType) {
	SECTION_TYPE_ALL,
    SECTION_TYPE_SYSTEM,
	SECTION_TYPE_USER,
	SECTION_TYPE_HIDDEN,
	SECTION_TYPE_VISIBLE,
	SECTION_TYPE_CUSTOM
};

#define kApplicationSectionTypeAll @"All"
#define kApplicationSectionTypeSystem @"System"
#define kApplicationSectionTypeUser @"User"
#define kApplicationSectionTypeHidden @"Hidden"
#define kApplicationSectionTypeVisible @"Visible"
#define kApplicationSectionTypeCustom @"Custom"

@interface ATLApplicationSection : NSObject
@property (nonatomic) ApplicationSectionType sectionType;
@property (nonatomic) NSPredicate* customPredicate;
@property (nonatomic) NSString* sectionName;

@property (nonatomic) NSArray* applicationsInSection;

+ (ApplicationSectionType)sectionTypeFromString:(NSString*)typeString;
+ (NSString*)stringFromSectionType:(ApplicationSectionType)sectionType;

+ (__kindof ATLApplicationSection*)applicationSectionWithDictionary:(NSDictionary*)sectionDictionary;
- (instancetype)_initWithDictionary:(NSDictionary*)sectionDictionary;
- (instancetype)initNonCustomSectionWithType:(ApplicationSectionType)sectionType;
- (instancetype)initCustomSectionWithPredicate:(NSPredicate*)predicate sectionName:(NSString*)sectionName;
- (NSArray<NSSortDescriptor*>*)sortDescriptorsForApplications;
- (void)populateFromAllApplications:(NSArray*)allApplications;

@end