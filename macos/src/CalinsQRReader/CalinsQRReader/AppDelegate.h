//
//  AppDelegate.h
//  CalinsQRReader
//
//  Created by calin on 11/25/18.
//  Copyright © 2018 Calin Culianu <calin.culianu@gmail.com>. MIT License.
//

#import <Cocoa/Cocoa.h>

@interface AppDelegate : NSObject <NSApplicationDelegate>
@property (nonatomic, weak) IBOutlet NSTextField *label;
@property (nonatomic, weak) IBOutlet NSButton *button;
- (IBAction) showAbout:(id)sender;
@end

