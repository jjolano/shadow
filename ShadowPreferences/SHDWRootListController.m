#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include "SHDWRootListController.h"

@implementation SHDWRootListController

- (NSArray *)specifiers {
	if (!_specifiers) {
		_specifiers = [[self loadSpecifiersFromPlistName:@"Root" target:self] retain];
	}

	return _specifiers;
}

- (void)generate_map:(id)sender {
	#ifdef DEBUG
	NSLog(@"[shadow] prefs: generating file map");
	#endif

	NSString *dpkg = @"/Library/dpkg/info";
	NSString *prefs = @"/var/mobile/Library/Preferences/me.jjolano.shadow.map.plist";
	NSArray *dpkg_list = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dpkg error:nil];

	if(dpkg_list) {
		NSMutableArray *blacklist = [NSMutableArray new];

		UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Shadow" message:@"Processing packages..." preferredStyle:UIAlertControllerStyleAlert];
		[self presentViewController:alert animated:YES completion:^{
			for(NSString *file in dpkg_list) {
				if([[file pathExtension] isEqualToString:@"list"]) {
					#ifdef DEBUG
					NSLog(@"[shadow] prefs: found dpkg list file %@", file);
					#endif

					NSString *contents = [NSString stringWithContentsOfFile:[NSString stringWithFormat:@"%@/%@", dpkg, file] encoding:NSUTF8StringEncoding error:NULL];

					if(contents) {
						NSArray *dpkg_files = [contents componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];

						for(NSString *dpkg_file in dpkg_files) {
							BOOL isDir;
							dpkg_file = [dpkg_file stringByStandardizingPath];

							if([[NSFileManager defaultManager] fileExistsAtPath:dpkg_file isDirectory:&isDir]) {
								if(!isDir
								|| [[dpkg_file pathExtension] isEqualToString:@"app"]
								|| [[dpkg_file pathExtension] isEqualToString:@"framework"]
								|| [[dpkg_file pathExtension] isEqualToString:@"bundle"]
								|| [[dpkg_file pathExtension] isEqualToString:@"theme"]) {
									[blacklist addObject:dpkg_file];
								}
							}
						}
					}
				}
			}

			NSMutableDictionary *prefs_map = [[NSMutableDictionary alloc] initWithContentsOfFile:prefs];

			if(prefs_map) {
				[prefs_map removeObjectForKey:@"blacklist"];
			} else {
				prefs_map = [NSMutableDictionary new];
			}

			prefs_map[@"blacklist"] = blacklist;
			[prefs_map writeToFile:prefs atomically:YES];

			#ifdef DEBUG
			NSLog(@"[shadow] prefs: wrote file map to %@", prefs);
			#endif
			
			[alert dismissViewControllerAnimated:YES completion:nil];
		}];
	} else {
		UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Shadow" message:@"Cannot generate file map: failed to open dpkg info directory." preferredStyle:UIAlertControllerStyleAlert];
		UIAlertAction *defaultAction = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil];
		[alert addAction:defaultAction];
		[self presentViewController:alert animated:YES completion:nil];
	}
}

@end
