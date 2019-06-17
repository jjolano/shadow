#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Preferences/PSListController.h>
#import <CepheiPrefs/HBRootListController.h>
#import <Cephei/HBPreferences.h>
#import <Cephei/HBRespringController.h>
#import "../Includes/Shadow.h"

#include <spawn.h>

@interface SHDWRootListController : HBRootListController
- (void)generate_map:(id)sender;
- (void)respring:(id)sender;
- (void)reset:(id)sender;
@end
