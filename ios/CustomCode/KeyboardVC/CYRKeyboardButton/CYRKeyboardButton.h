//
//  CYRKeyboardButton.h
//
//  Created by Illya Busigin on 7/19/14.
//  Copyright (c) 2014 Cyrillian, Inc.
//  Portions Copyright (c) 2013 Nigel Timothy Barber (TurtleBezierPath)
//
//  Distributed under MIT license.
//  Get the latest version from here:
//
//  https://github.com/illyabusigin/CYRKeyboardButton
//
// The MIT License (MIT)
//
// Copyright (c) 2014 Cyrillian, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#import <UIKit/UIKit.h>

typedef NS_ENUM(NSUInteger, CYRKeyboardButtonPosition) {
    CYRKeyboardButtonPositionLeft,
    CYRKeyboardButtonPositionInner,
    CYRKeyboardButtonPositionRight,
    CYRKeyboardButtonPositionCount
};

/**
 The style of the keyboard button. You use these constants to set the value of the keyboard button style.
 */
typedef NS_ENUM(NSUInteger, CYRKeyboardButtonStyle) {
    /** Keyboard buttons are styled like iPhone keyboard buttons. */
    CYRKeyboardButtonStylePhone,
    /** Keyboard buttons are styled like iPad keyboard buttons. */
    CYRKeyboardButtonStyleTablet
};

/** 
 Notifies observers that the keyboard button has been pressed. The affected button is stored in the object parameter of the notification. The userInfo dictionary contains the pressed key and can be accessed with the CYRKeyboardButtonKeyPressedKey key.
 */
extern NSString *const CYRKeyboardButtonPressedNotification;

/** 
 Notifies observers that the keyboard button has show the expanded input view. The affected button is stored in the object parameter of the notification.
 */
extern NSString *const CYRKeyboardButtonDidShowExpandedInputNotification;

/**
 Notifies observers that the keyboard button has hidden the expanded input view. The affected button is stored in the object parameter of the notification.
 */
extern NSString *const CYRKeyboardButtonDidHideExpandedInputNotification;

/**
 The key used to fetch the pressed key string from the userInfo dictionary returned when CYRKeyboardButtonPressedNotification is fired.
 */
extern NSString *const CYRKeyboardButtonKeyPressedKey;

/**
 CYRKeyboardButton is a drop-in keyboard button that mimics the look, feel, and functionality of the native iOS keyboard buttons. This button is highly configurable via a variety of styling properties which conform to the UIAppearance protocol.
 */
@interface CYRKeyboardButton : UIControl

/**
 The style of the keyboard button. This determines the basic visual appearance of the keyboard.
 @discussion The style value is automatically determined during initialization but can be overriden.
 */
@property (nonatomic, assign) CYRKeyboardButtonStyle style;


// Styling

/**
 The font associated with the keyboard button.
 @discussion This font only affects the keyboard button's standard view.
 */
@property (nonatomic, strong) UIFont *font UI_APPEARANCE_SELECTOR;

/**
 The font associated with the keyboard button input options.
 */
@property (nonatomic, strong) UIFont *inputOptionsFont UI_APPEARANCE_SELECTOR;

/**
 The default color of the keyboard button.
 */
@property (nonatomic, strong) UIColor *keyColor UI_APPEARANCE_SELECTOR;

/**
 The text color of the keyboard button.
 @discussion This color affects both the standard and input option text.
 */
@property (nonatomic, strong) UIColor *keyTextColor UI_APPEARANCE_SELECTOR;

/**
 The shadow color for the keyboard button.
 */
@property (nonatomic, strong) UIColor *keyShadowColor UI_APPEARANCE_SELECTOR;

/**
 The highlighted background color of the keyboard button.
 */
@property (nonatomic, strong) UIColor *keyHighlightedColor UI_APPEARANCE_SELECTOR;

/**
 The position of the keyboard button. This is used to determine where to place the popover key views and is automatically determined when the keyboard button is added to a view and update during layout changes.
 */
@property (nonatomic, readonly) CYRKeyboardButtonPosition position;

// Configuration

/**
 The string input for the keyboard button. This is the string that would be inserted upon a successful key press.
 */
@property (nonatomic, strong) NSString *input;

/**
 An array of input option strings associated with the keybonard button. The user must tap and hold the keyboard button for 0.3 seconds before the input options will be displayed.
 @discussion Input options are automatically positioned based on the keyboard buttons position within its' superview.
 */
@property (nonatomic, strong) NSArray *inputOptions;

/**
 An object that adopts the UITextInput protocol. When a key is pressed the key value is automatically inserted via the textInput object.
 @discussion If the textInput object is not the first responder no text will be inserted.
 */
@property (nonatomic, weak) id<UITextInput> textInput;

@property (nonatomic) BOOL keyRepeat;

@property (nonatomic, copy) void(^textInputCallback)(NSString *text);
@property (nonatomic, copy) void(^keyPushedCallback)(void); // sent when the key is depressed but before user releases finger
@property (nonatomic, copy) void(^keyReleasedCallback)(void); // sent when the touches end and the key is released

@end
