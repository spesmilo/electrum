//
//  ComboDrawerPicker.h
//  Electron-Cash
//
//  Created by calin on 5/22/18.
//  Copyright © 2018 Calin Culianu <calin.culianu@gmail.com>.
//  MIT License
//
#ifndef CustomDrawerPicker_H
#define CustomDrawerPicker_H
#import <UIKit/UIKit.h>

@interface ComboDrawerPicker : UIViewController {
    IBOutlet __weak UILabel *_titLbl;
    IBOutlet __weak UITableView *_tv;
    IBOutlet __weak NSLayoutConstraint *_topCS, *_lmarginCS, *_rmarginCS, *_bottomHeightCS;
    IBOutlet __weak UIView *_bottomView;
    IBOutlet __weak UIImageView *_chevron;
}
@property (nonatomic, copy) NSArray<NSString *> *items; // the items to put in the combobox. (items counts <= 4 will vertically fit without the user needing to scroll)
@property (nonatomic, copy) NSString *topTitle; // the title eg "Status:" part of "Status: Unused"
@property (nonatomic) BOOL flushLeft; // if true, flush the top tab to the left, otherwise it's flush right. Default NO
@property (nonatomic) BOOL opened; // opens/closes it (animated) if set, otherwise returns current isOpen state. Default NO
@property (nonatomic) NSUInteger selection; // the current selected index. set it to change the selection
@property (nonatomic, copy) void (^selectedBlock)(NSInteger selection); // optional callback to call whenever the selection changes.
@property (nonatomic, copy) void (^openClosedBlock)(BOOL isOpen); // optional callback to call whenever the drawer is opened/closed
@property (nonatomic, copy) void (^backgroundTappedBlock)(CGPoint locationInThisVCsView); // the point passed-in is in thisVC.view's coordinate space.
@property (nonatomic, copy) void (^controlTappedBlock)(void); // called whenever the user taps the top title control area. If autoOpenCloseOnTap is true, toggleOpen will also be called
@property (nonatomic, copy) UIColor *colorTitle, *colorTitle2, *colorItems;
@property (nonatomic) BOOL autoOpenCloseOnTap; // iff true, calls [self toggleOen] automatically when the top drawer is tapped. the controlTappedBlock() callback is always called regardless. Defaults NO
@property (nonatomic, readonly) NSAttributedString *attributedStringForTopTitle; /// generates an attributed string based on the current selected item, colorTitle, and colorTitle2.  Useful for putting into a UILabel in the stub proxy view used to represent this viewcontroller.
@property (nonatomic, readonly) UIView *bottomView; // used in hacky code in addresses.py for display flicker prevention when switching drawer tabs
- (void) toggleOpen;

- (void)openAnimated:(BOOL)animated;
- (void)closeAnimated:(BOOL)animated;
@end

#endif // CustomDrawerPicker_H

