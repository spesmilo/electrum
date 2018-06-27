//
//  ECTextViewDelegate.h
//  Electron-Cash
//
//  Created by calin on 5/25/18.
//  Copyright © 2018 Calin Culianu. MIT License.
//

#import <UIKit/UIKit.h>

/// A textview delegate that auto-places some placeholder text when it's empty and calls callbacks for you on
/// textViewDidBeginEditing and textViewDidEndEditing.  Note this class was hacked together quickly so be sure to
/// set all properties in IB or before you start using the textview (as setup code). Setting properties after it runs
/// may or may not work correctly.
@interface ECTextViewDelegate : NSObject<UITextViewDelegate>

@property (nonatomic, copy) NSString *placeholderText;
@property (nonatomic, copy) UIFont *placeholderFont;
@property (nonatomic, copy) UIColor *placeholderColor;
@property (nonatomic) BOOL centerPlaceholder; /// if true, placeholder is center aligned, if false, aligned to tv

@property (nonatomic, copy) NSString *text; // not valid during editing
@property (nonatomic, copy) UIFont *font;
@property (nonatomic, copy) UIColor *color;
@property (nonatomic, copy) NSParagraphStyle *paragraphStyle; /// if set, the paragraph style to apply to the text

@property (nonatomic) BOOL dontStrip; ///< if true, don't strip whitespace

// do not assign to tv.text directly.  instead, use the properties above
@property (nonatomic, weak) IBOutlet UITextView *tv;

@property (nonatomic, copy) void (^didBeginEditing)(void);
@property (nonatomic, copy) void (^didEndEditing)(NSString *newText);
@property (nonatomic, copy) void (^didChange)(void);

@end

