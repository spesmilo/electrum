/*
 * QRCodeReaderViewController
 *
 * Copyright 2014-present Yannick Loriot.
 * http://yannickloriot.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#import <UIKit/UIKit.h>

/**
 * The camera switch button.
 * @since 2.0.0
 */
@interface QRCameraSwitchButton : UIButton

#pragma mark - Managing Properties
/** @name Managing Properties */

/**
 * @abstract The edge color of the drawing.
 * @discussion The default color is the white.
 * @since 2.0.0
 */
@property (nonatomic, strong) UIColor *edgeColor;

/**
 * @abstract The fill color of the drawing.
 * @discussion The default color is the darkgray.
 * @since 2.0.0
 */
@property (nonatomic, strong) UIColor *fillColor;

/**
 * @abstract The edge color of the drawing when the button is touched.
 * @discussion The default color is the white.
 * @since 2.0.0
 */
@property (nonatomic, strong) UIColor *edgeHighlightedColor;

/**
 * @abstract The fill color of the drawing when the button is touched.
 * @discussion The default color is the black.
 * @since 2.0.0
 */
@property (nonatomic, strong) UIColor *fillHighlightedColor;

@end
