//
//  UIViewExtras.h
//
//  Created by calin on 9/29/09.
//  Copyright 2009 Calin Culianu <calin.culianu@gmail.com>. MIT License.
//

#import <UIKit/UIKit.h>


@interface UIView (AnimExtras)
/// returns true IFF the receiver is currently animating
@property (nonatomic, readonly) BOOL hasAnimations;

/// Adds this view to parent view, and slides it into existence from the bottom; makes it the first responder.
- (void) modalSlideFromBottomIntoView:(UIView *)parentView;
/// Identical to above but also with a callback which is called when done.  Callback takes 1 argument, this view itself.
- (void) modalSlideFromBottomIntoView:(UIView *)parentView target:(id)callback_target selector:(SEL)callback;
/// Slides the view out the bottom and removes it from parent when animation is done; resigns first responder.
- (void) modalSlideOutToBottom;
/// Same as above but also with callback when animation is done.  Callback take 1 argument, this UIView itself.
- (void) modalSlideOutToBottomWithTarget:(id)target selector:(SEL)selector;
/// Animate oscillate action -- a good default speed is 10.0
- (void) animateShake:(NSUInteger)nShakes speed:(CGFloat)speed displacement:(CGFloat)disp randPerturbAmount:(CGFloat)pert;
/// Unhides and fades receiver in, fading out `otherView'.  Hides `otherView' when done
- (void) fadeInWhileFadingOutOther:(UIView *)otherView;
/// Renders this entire view to an image, returns the autoreleased image
- (UIImage *) renderToImage;
/// Same as above, but just for a subrect of the view
- (UIImage *) renderToImage:(CGRect)rectInView;
/// Animates a view's background from a particular color to another color (if reverses=YES then it animates it back to start as well)
-(void) backgroundColorAnimationFromColor:(UIColor *)startColor
                                  toColor:(UIColor *)destColor
                                 duration:(CGFloat)duration
                                 reverses:(BOOL)reverses /**< iff true will go startColor -> destColor and back in duration seconds */
                               completion:(void(^)(void))completion;

-(void) backgroundColorAnimationToColor:(UIColor *)destColor
                                 duration:(CGFloat)duration
                                 reverses:(BOOL)reverses
                               completion:(void(^)(void))completion;
@end

@interface UILabel (MiscEffects)
-(void) textColorAnimationFromColor:(UIColor *)startColor
                            toColor:(UIColor *)destColor
                           duration:(CGFloat)duration
                           reverses:(BOOL)reverses
                         completion:(void(^)(void))completion;

-(void) textColorAnimationToColor:(UIColor *)destColor
                         duration:(CGFloat)duration
                         reverses:(BOOL)reverses
                       completion:(void(^)(void))completion;
@end

typedef void(^ActionBlock)(id);
@interface UIControl (UIControlBlockAction)
- (void)handleControlEvent:(UIControlEvents)event withBlock:(ActionBlock)block;
@end

@interface UIGestureRecognizer (BlockSupport)
- (void)addBlock:(ActionBlock)block;
@end

@interface UIView (ViewRecursion)
- (NSArray *) allSubviewsRecursively;
@end

@interface UIView (Mogrification)
- (void) affineScaleX:(CGFloat)scaleX scaleY:(CGFloat)scaleY;
- (void) affineScale:(CGPoint)xyScale;
@end

@interface ForwardingDelegate : NSObject
@property (nonatomic, weak) id<NSObject> fwdDelegate;
- (instancetype) initWithDelegate:(id<NSObject>)fwd;
@end

@interface UILabel (TextKerning)
/**
 * Set the label's text to the given string, using the given kerning value if able.
 * (i.e., if running on iOS 6.0+). The kerning value specifies the number of points
 * by which to adjust spacing between characters (positive values increase spacing,
 * negative values decrease spacing, a value of 0 is default)
 **/
- (void) setText:(NSString *)text withKerning:(CGFloat)kerning;

/**
 * Set the kerning value of the currently-set text.  The kerning value specifies the number of points
 * by which to adjust spacing between characters (positive values increase spacing,
 * negative values decrease spacing, a value of 0 is default)
 **/
- (void) setKerning:(CGFloat)kerning;
@end

@interface UIColor (DeviceRGB)
/**
 * Returns a UIColor specified by components in device RGB color space.
 * (Workaround to UIColor expecting extended color space and Max giving me device color space colors.)
 **/
+ (UIColor *) colorInDeviceRGBWithRed:(CGFloat)red green:(CGFloat)green blue:(CGFloat)blue alpha:(CGFloat)alpha;
/**
 * Returns a UIColor specified by components in device RGB color space, using an html-like hex format eg:
 * @"#ffcc99" or @"cc33ff" or @"#7799cccc" (with alpha at end).  Leading/trailing whitespace is ignored.
 **/
+ (UIColor *) colorInDeviceRGBWithHexString:(NSString *)hexString;
@end

@interface LinkLabel : UILabel
@property (nonatomic, readonly, weak) UIGestureRecognizer *gr; // the tap gesture recognizer for the link
@property (nonatomic, copy) NSString *linkText; // set this instead of .text or .attributedText to generate an underlined label that is clickable. Be sure to set .textColor to something blue-ish
@property (nonatomic, copy) void(^linkWillAnimate)(LinkLabel *); // called right before the link animation begins
@property (nonatomic, copy) void(^linkTarget)(LinkLabel *); // the action for the link
@property (nonatomic, copy) UIColor *normalColor, // the color the link flashes from, defaults to whatever the .textColor was when tapped but if set explicitly, will be a different color
                                    *highlightedColor, // the color the link flashes to. Defaults to white. Set it to something purplish
                                    *disabledColor; // the color the link should be when .linkDistabled = YES
@property (nonatomic) CGFloat duration; // the duration of the link animation.  defaults to 0.3 seconds
@property (nonatomic) BOOL linkDisabled; // if true, will draw the link as not underlined, using .textColor, and it won't respond to touches.  Use this to sometimes disable a link for some screens. Defaults to NO.
@end

@interface UIResponder (FirstResponder)
+ (id) currentFirstResponder;
@end

/* Support for setFrozen method which was used in original EC Qt implementation.
   If set to true: 1. Makes the text field read-only and 2. Sets the border to a line border.
   Setting to false undoes the above, restoring the original border
   (NB: The original borderStyle setting gets saved to self.ECPvtData). */
@interface UITextField(ECLibCompatFreeze)
- (void)setFrozen:(BOOL)frozen;
- (BOOL)isFrozen;
@end

// Support for adding arbitrary dictionary items at runtime to any NSObject
@interface NSObject(ECPrivateData)
@property (nonatomic, readonly, getter=getnsobjectECPvtData) NSMutableDictionary *ECPvtData;
@end
