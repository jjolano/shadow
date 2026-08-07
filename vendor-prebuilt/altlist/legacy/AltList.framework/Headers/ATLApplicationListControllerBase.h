#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>
#import "ATLApplicationSection.h"

@class LSApplicationProxy;

@interface PSListController()
- (BOOL)containsSpecifier:(PSSpecifier*)specifier;
@end

@protocol LSApplicationWorkspaceObserverProtocol <NSObject>
@optional
-(void)applicationsDidInstall:(id)arg1;
-(void)applicationsDidUninstall:(id)arg1;
@end

@interface ATLApplicationListControllerBase : PSListController <UISearchResultsUpdating, LSApplicationWorkspaceObserverProtocol>
{
	dispatch_queue_t _iconLoadQueue;
	NSMutableArray* _allSpecifiers;
	NSMutableDictionary* _specifiersByLetter;
	NSArray<ATLApplicationSection*>* _applicationSections;
	UISearchController* _searchController;
	NSString* _searchKey;
	BOOL _isPopulated;
	BOOL _isReloadingSpecifiers;
	NSBundle* _altListBundle;
	UIImage* _placeholderAppIcon;
}

@property (nonatomic) BOOL useSearchBar;
@property (nonatomic) BOOL hideSearchBarWhileScrolling;
@property (nonatomic) BOOL includeIdentifiersInSearch;
@property (nonatomic) BOOL showIdentifiersAsSubtitle;
@property (nonatomic) BOOL alphabeticIndexingEnabled;
@property (nonatomic) BOOL hideAlphabeticSectionHeaders;
@property (nonatomic) NSBundle* localizationBundle;

- (instancetype)initWithSections:(NSArray<ATLApplicationSection*>*)applicationSections;

- (void)_setUpSearchBar;
- (void)_loadSectionsFromSpecifier;
- (void)_populateSections;

- (void)loadPreferences;
- (void)prepareForPopulatingSections;
- (NSString*)localizedStringForString:(NSString*)string;
- (void)reloadApplications;

- (BOOL)shouldHideApplicationSpecifiers;
- (BOOL)shouldHideApplicationSpecifier:(PSSpecifier*)specifier;

- (BOOL)shouldShowSubtitles;
- (NSString*)subtitleForApplicationWithIdentifier:(NSString*)applicationID;
- (NSString*)_subtitleForSpecifier:(PSSpecifier*)specifier;

- (PSCellType)cellTypeForApplicationCells;
- (Class)customCellClassForCellType:(PSCellType)cellType;
- (Class)detailControllerClassForSpecifierOfApplicationProxy:(LSApplicationProxy*)applicationProxy;
- (SEL)getterForSpecifierOfApplicationProxy:(LSApplicationProxy*)applicationProxy;
- (SEL)setterForSpecifierOfApplicationProxy:(LSApplicationProxy*)applicationProxy;

- (PSSpecifier*)createSpecifierForApplicationProxy:(LSApplicationProxy*)applicationProxy;
- (NSArray*)createSpecifiersForApplicationSection:(ATLApplicationSection*)section;
- (PSSpecifier*)createGroupSpecifierForApplicationSection:(ATLApplicationSection*)section;

- (NSMutableArray*)specifiersGroupedByLetters;
- (void)populateSpecifiersByLetter;

- (PSSpecifier*)specifierForApplicationWithIdentifier:(NSString*)applicationID;
- (NSIndexPath*)indexPathForApplicationWithIdentifier:(NSString*)applicationID;

@end