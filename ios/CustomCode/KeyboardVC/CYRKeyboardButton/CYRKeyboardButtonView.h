//
//  CYRKeyboardButtonView.h
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

typedef NS_ENUM(NSUInteger, CYRKeyboardButtonViewType) {
    CYRKeyboardButtonViewTypeInput,
    CYRKeyboardButtonViewTypeExpanded
};

@class CYRKeyboardButton;

@interface CYRKeyboardButtonView : UIView

@property (nonatomic, readonly) CYRKeyboardButtonViewType type;
@property (nonatomic, readonly) NSInteger selectedInputIndex;

- (instancetype)initWithKeyboardButton:(CYRKeyboardButton *)button type:(CYRKeyboardButtonViewType)type;
- (void)updateSelectedInputIndexForPoint:(CGPoint)point;

@end
