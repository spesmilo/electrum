//
//  DZNSegmentedControl.h
//  DZNSegmentedControl
//  https://github.com/dzenbot/DZNSegmentedControl
//
//  Created by Ignacio Romero Zurbuchen on 3/4/14.
//  Copyright (c) 2014 DZN Labs. All rights reserved.
//  Licence: MIT-Licence
//

#import <UIKit/UIKit.h>

@protocol DZNSegmentedControlDelegate;

enum {
    // segment index for no selected segment
    DZNSegmentedControlNoSegment = -1
};

/**
 A drop-in replacement for UISegmentedControl showing multiple segment counts, to be used typically on a user profile.
 */
@interface DZNSegmentedControl : UIControl <UIBarPositioning, UIAppearance>

/** The control's delegate object, conforming to the UIBarPositioning protocol. */
@property (nonatomic, weak) IBOutlet id <DZNSegmentedControlDelegate> delegate;
/** The items displayed on the control. */
@property (nonatomic, retain) NSArray *items;
/** The index number identifying the selected segment (that is, the last segment touched). */
@property (nonatomic) NSInteger selectedSegmentIndex;
/** Returns the number of segments the receiver has. */
@property (nonatomic, readonly) NSUInteger numberOfSegments;
/** The height of the control. Default is 56 points, and if not showing counts, default is 30 points. */
@property (nonatomic, readwrite) CGFloat height UI_APPEARANCE_SELECTOR;
/** The width of the control. Default is superview's width. */
@property (nonatomic, readwrite) CGFloat width UI_APPEARANCE_SELECTOR;
/** The height of the selection indicator. Default is 2 points. */
@property (nonatomic, readwrite) CGFloat selectionIndicatorHeight UI_APPEARANCE_SELECTOR;
/** The padding height of the selection indicator from the title of the button. Default is 0 points. */
@property (nonatomic, readwrite) CGFloat selectionIndicatorPadding UI_APPEARANCE_SELECTOR;
/** The duration of the indicator's animation. Default is 0.2 sec. */
@property (nonatomic, readwrite) CGFloat animationDuration UI_APPEARANCE_SELECTOR;
/** The font family to be used on labels. Default is system font (HelveticaNeue). Font size is managed by the class. */
@property (nonatomic, retain) UIFont *font UI_APPEARANCE_SELECTOR;
/** The color of the hairline. Default is light gray. To hide the hairline, just set clipsToBounds to YES, like you would do it for UIToolBar & UINavigationBar. */
@property (nonatomic, readwrite) UIColor *hairlineColor UI_APPEARANCE_SELECTOR;
/** The custom number formatter used to format the count values. A default number formatter will be used if this property is nil. If this property is set, it takes precedence over the showsGroupingSeparators flag. */
@property (nonatomic, strong) NSNumberFormatter *numberFormatter;
/** YES to display the count number on top of the titles. Default is YES. */
@property (nonatomic) BOOL showsCount;
/** YES to adjust the width of the selection indicator on the title width. Default is YES. */
@property (nonatomic) BOOL autoAdjustSelectionIndicatorWidth;
/** YES if the title should display on top of the count. Default is NO. */
@property (nonatomic) BOOL inverseTitles;
/** YES to make the selection indicator animation bouncy. Default is NO. */
@property (nonatomic) BOOL bouncySelectionIndicator;
/** YES to format the counts with grouping separators. Default is NO. */
@property (nonatomic) BOOL showsGroupingSeparators;
/** YES if the font size should be reduced in order to fit the title string into the segment's width. Default is NO. */
@property (nonatomic) BOOL adjustsFontSizeToFitWidth;
/** YES if the button top inset should be adjusted based on bar position (top or bottom). Default is YES. */
@property (nonatomic) BOOL adjustsButtonTopInset;
/** YES if the selected segment is user interaction disabled. NO if touching the segment button should still forward the actions to its targets without animating the selection indicator. Default is YES. */
@property (nonatomic) BOOL disableSelectedSegment;

/**
 Initializes and returns a segmented control with segments having the given titles or images.
 The returned segmented control is automatically sized to fit its content within the width of its superview.
 If items is nil, the control will still be created but expecting titles and counts or images to be assigned.
 
 @params items An array of NSString objects only.
 @returns A DZNSegmentedControl object or nil if there was a problem in initializing the object.
 */
- (instancetype)initWithItems:(NSArray *)items;

/**
 Sets the selected segment index programatically, optionally animated.
 
 @param segment The new segment to select.
 @param animated YES if the selection should animate the selection indicator's position.
 */
- (void)setSelectedSegmentIndex:(NSInteger)segment animated:(BOOL)animated;

/**
 Sets the tint color of a segment.
 
 @param tintColor A color to rendered for the segment's background color.
 @param segment An index number identifying a segment in the control. It must be a number between 0 and the number of segments (numberOfSegments) minus 1; values exceeding this upper range are pinned to it.
 */
- (void)setTintColor:(UIColor *)tintColor forSegmentAtIndex:(NSUInteger)segment;

/**
 Sets the title of a segment.
 A segment can only have an image or a title; it can’t have both. There is no default title.
 
 @param title A string to display in the segment as its title.
 @param segment An index number identifying a segment in the control. It must be a number between 0 and the number of segments (numberOfSegments) minus 1; values exceeding this upper range are pinned to it.
 */
- (void)setTitle:(NSString *)title forSegmentAtIndex:(NSUInteger)segment;

/**
 Sets the title color for a particular state.
 
 @param color A color to be rendered for each the segment's state.
 @param state The state that uses the styled title. The possible values are described in UIControlState.
 */
- (void)setTitleColor:(UIColor *)color forState:(UIControlState)state;

/**
 Sets the count of a segment.
 
 @param count A number to display in the segment as its count.
 @param segment An index number identifying a segment in the control. It must be a number between 0 and the number of segments (numberOfSegments) minus 1; values exceeding this upper range are pinned to it.
 */
- (void)setCount:(NSNumber *)count forSegmentAtIndex:(NSUInteger)segment;

/**
 Sets the content of a segment to a given image.
 A segment can only have an image or a title; it can’t have both. There is no default image.

 @param image An image object to display in the segment.
 @param segment An index number identifying a segment in the control. It must be a number between 0 and the number of segments (numberOfSegments) minus 1; values exceeding this upper range are pinned to it.
 */
- (void)setImage:(UIImage *)image forSegmentAtIndex:(NSUInteger)segment;

/**
 Enables the specified segment.
 
 @param enabled YES to enable the specified segment or NO to disable the segment. By default, segments are enabled.
 @param segment An index number identifying a segment in the control. It must be a number between 0 and the number of segments (numberOfSegments) minus 1; values exceeding this upper range are pinned to it.
 */
- (void)setEnabled:(BOOL)enabled forSegmentAtIndex:(NSUInteger)segment;


/**
  Returns whether the given segment is selected or not
 
 @param segment An index number identifying a segment in the control. It must be a number between 0 and the number of segments (numberOfSegments) minus 1; values exceeding this upper range are pinned to it.
 @returns Returns whether the given segment is selected or not
 */
- (BOOL)isSegmentAtIndexEnabled:(NSUInteger)segment;

/**
 Sets a contentOffset and contentSize to enable scrollView tracking.
 To be used in combination with UIScrollView+DZNSegmentedControl.
 
 @param scrollOffset The tracking scrollView's contentOffset
 @param contentSize The tracking scrollView's contentSize
 */
- (void)setScrollOffset:(CGPoint)scrollOffset contentSize:(CGSize)contentSize;

/**
 Returns the title of the specified segment.
 
 @param segment An index number identifying a segment in the control. It must be a number between 0 and the number of segments (numberOfSegments) minus 1; values exceeding this upper range are pinned to it.
 @returns Returns the string (title) assigned to the receiver as content. If no title has been set, it returns nil.
 */
- (NSString *)titleForSegmentAtIndex:(NSUInteger)segment;

/**
 Returns the count of the specified segment.
 
 @param segment An index number identifying a segment in the control. It must be a number between 0 and the number of segments (numberOfSegments) minus 1; values exceeding this upper range are pinned to it.
 @returns Returns the number (count) assigned to the receiver as content. If no count has been set, it returns 0.
 */
- (NSNumber *)countForSegmentAtIndex:(NSUInteger)segment;

/**
 Removes all segments of the receiver
 */
- (void)removeAllSegments;

@end

typedef NS_ENUM(NSInteger, DZNScrollDirection) {
    DZNScrollDirectionHorizontal,
    DZNScrollDirectionVertical
};

@class DZNSegmentedControl;

@interface UIScrollView (DZNSegmentedControl)

/** The scrolling direction of the scrollView. Default is Horizontal. */
@property (nonatomic) DZNScrollDirection scrollDirection;

/** YES if the scrollview should scroll automatically when a segment changes. Default is YES. */
@property (nonatomic) BOOL scrollOnSegmentChange;

/** The scrollView reference to observe the content offset updates and interact with. */
@property (nonatomic, weak) DZNSegmentedControl *segmentedControl;

@end

/**
 This protocol conforms to the UIBarPositioningDelegate protocol to support the any directional decoration drawing accordingly (ie: the hairline and the selection indicator bar).
 */
@protocol DZNSegmentedControlDelegate <UIBarPositioningDelegate>
@optional

/**
 Implement this method to position the selector indicator either at the top or bottom of the view. Default is UIBarPositionAny which means the selector indicator will be placed at the bottom. If not implemented, the value for positionForBar: will be used instead.
 */
- (UIBarPosition)positionForSelectionIndicator:(id<UIBarPositioning>)bar;

@end
