//
//  CWStatusBarNotification
//  CWNotificationDemo
//
//  Created by Cezary Wojcik on 11/15/13.
//  Copyright (c) 2015 Cezary Wojcik. MIT License.
//

#import <UIKit/UIKit.h>

/**
 * @brief A simple completion used for handling tapping the notification.
 */
typedef void(^CWCompletionBlock)(void);

# pragma mark - ScrollLabel

/**
 * A subclass of @c UILabel that scrolls the text if it is too long for the 
 * label.
 */
@interface ScrollLabel : UILabel
/**
 * Used to find the amount of time that the label will spend scrolling.
 * @return The amount of time that will be spent scrolling.
 */
- (CGFloat)scrollTime;
@end

# pragma mark - CWWindowContainer

/**
 * A subclass of @c UIWindow that overrides the @c hitTest method in order to 
 * allow tap events to pass through the window.
 */
@interface CWWindowContainer : UIWindow
/// The height of the notification that is being displayed in the window.
@property (assign, nonatomic) CGFloat notificationHeight;
@end

# pragma mark - CWViewController

/**
 * A subclass of @c UIViewController that allows handing over
 * @c supportedInterfaceOrientations if needed.
 */
@interface CWViewController : UIViewController
/// Indicates the preferred status bar style.
@property (nonatomic) UIStatusBarStyle preferredStatusBarStyle;
/// Indicats the supported interface orientations.
@property (nonatomic, setter=setSupportedInterfaceOrientations:)
    UIInterfaceOrientationMask supportedInterfaceOrientations;
@end

# pragma mark - CWStatusBarNotification

/**
 * A subclass of @c NSObject that is responsible for managing status bar
 * notifications.
 */
@interface CWStatusBarNotification : NSObject

# pragma mark - enums

/**
 * @typedef CWNotificationStyle
 * @brief Determines the notification style.
 */
typedef NS_ENUM(NSInteger, CWNotificationStyle) {
    /// Covers the status bar portion of the screen.
    CWNotificationStyleStatusBarNotification,
    /// Covers the status bar and navigation bar portions of the screen.
    CWNotificationStyleNavigationBarNotification
};

/**
 * @typedef CWNotificationAnimationStyle
 * @brief Determines the direction of animation for the notification.
 */
typedef NS_ENUM(NSInteger, CWNotificationAnimationStyle) {
    /// Animate in from the top or animate out to the top.
    CWNotificationAnimationStyleTop,
    /// Animate in from the bottom or animate out to the bottom.
    CWNotificationAnimationStyleBottom,
    /// Animate in from the left or animate out to the left.
    CWNotificationAnimationStyleLeft,
    /// Animate in from the right or animate out to the right.
    CWNotificationAnimationStyleRight
};

/**
 * @typedef CWNotificationAnimationType
 * @brief Determines whether the notification moves the existing content out of
 * the way or simply overlays it.
 */
typedef NS_ENUM(NSInteger, CWNotificationAnimationType) {
    /// Moves existing content out of the way.
    CWNotificationAnimationTypeReplace,
    /// Overlays existing content.
    CWNotificationAnimationTypeOverlay
};

# pragma mark - properties

/// The label that holds the notification text.
@property (strong, nonatomic) ScrollLabel *notificationLabel;
/// The @c UIView that holds a screenshot of the status bar view.
@property (strong, nonatomic) UIView *statusBarView;
/// The block that gets triggered when the notification is tapped.
@property (copy, nonatomic) CWCompletionBlock notificationTappedBlock;
/// Indicates whether the notification is currently being shown.
@property (nonatomic) BOOL notificationIsShowing;
/// Indicates whether the notification is currently dismissing.
@property (nonatomic) BOOL notificationIsDismissing;
/// The window that holds the notification.
@property (strong, nonatomic) CWWindowContainer *notificationWindow;

/**
 * The background color of the notification label. Default value is the tint
 * color of the application's main window.
 */
@property (strong, nonatomic) UIColor *notificationLabelBackgroundColor;
/**
 * The text color of the notification label. Default value is white.
 */
@property (strong, nonatomic) UIColor *notificationLabelTextColor;
/**
 * The font of the notification label. Default value is system font.
 */
@property (strong, nonatomic) UIFont *notificationLabelFont;
/**
 * Allows setting a custom height for the notification label. If this value is
 * 0, the height will be determined by the @c notificationStyle. Default value
 * is 0.
 */
@property (assign, nonatomic) CGFloat notificationLabelHeight;
/**
 * The custom view to present if using @c displayNotificationWithView. Default
 * value is @c nil.
 */
@property (strong, nonatomic) UIView *customView;
/**
 * Determines whether the notification text has multiple lines. Default value is
 * @c NO.
 */
@property (assign, nonatomic) BOOL multiline;
/**
 * The supported interface orientations. Default value is the
 * @c supportedInterfaceOrientations value of the root view controller of the
 * application.
 */
@property (nonatomic) UIInterfaceOrientationMask supportedInterfaceOrientations;
/**
 * The amount of time that it takes to animate the notification in or out.
 * Default value is 0.25.
 */
@property (nonatomic) NSTimeInterval notificationAnimationDuration;
/**
 * Determines whether the notification covers the status bar or both the status
 * bar and the navigation bar. Default value is 
 * @c CWNotificationStyleStatusBarNotification.
 */
@property (nonatomic) CWNotificationStyle notificationStyle;
/**
 * Determines the direction from which the notification animates in. Default
 * value is @c CWNotificationAnimationStyleBottom.
 */
@property (nonatomic) CWNotificationAnimationStyle notificationAnimationInStyle;
/**
 * Determines the direction from which the notification animates out. Default
 * value is @c CWNotificationAnimationStyleBottom.
 */
@property (nonatomic) CWNotificationAnimationStyle
    notificationAnimationOutStyle;
/**
 * Determines whether the the notification's animation replaces the existing 
 * content or overlays it. Default value is 
 * @c CWNotificationAnimationTypeReplace.
 */
@property (nonatomic) CWNotificationAnimationType notificationAnimationType;
/**
 * The preferred status bar style. Default value is @c UIStatusBarStyleDefault.
 */
@property (nonatomic) UIStatusBarStyle preferredStatusBarStyle;

#pragma mark - methods

/**
 * Displays a notification with the indicated message and then performs the
 * completion block once the notification animates in.
 * @param message
 *        The content of the message to be displayed.
 * @param completion
 *        The block to be invoked once the notification is displayed.
 */
- (void)displayNotificationWithMessage:(NSString *)message
                            completion:(void (^)(void))completion;

/**
 * Displays a notification with the indicated message for the indicated
 * duration.
 * @param message
 *        The content of the message to be displayed.
 * @param duration
 *        The amount of seconds for which the notification should be displayed,
 *        not including the animate in and out times.
 */
- (void)displayNotificationWithMessage:(NSString *)message
                           forDuration:(NSTimeInterval)duration;

/**
 * Displays a notification with the indicated message for the indicated
 * duration.  Calls optional dismissedCompletion upon dismissal completion.
 * @param message
 *        The content of the message to be displayed.
 * @param duration
 *        The amount of seconds for which the notification should be displayed,
 *        not including the animate in and out times.
 * @param dismissedCompletion
 *        If not nil, the block to call upon dismissal (after duration seconds).
 */
- (void)displayNotificationWithMessage:(NSString *)message forDuration:(NSTimeInterval)duration
                   dismissedCompletion:(void (^)(void))dismissedCompletion;

/**
 * Displays a notification with the indicated attributed string and then 
 * performs the completion block once the notification animates in.
 * @param attributedString
 *        The content of the message to be displayed.
 * @param completion
 *        The block to be invoked once the notification is displayed.
 */
- (void)displayNotificationWithAttributedString:(NSAttributedString *)
                                                attributedString
                                     completion:(void (^)(void))completion;

/**
 * Displays a notification with the indicated message for the indicated
 * duration.
 * @param attributedString
 *        The content of the message to be displayed.
 * @param duration
 *        The amount of seconds for which the notification should be displayed,
 *        not including the animate in and out times.
 */
- (void)displayNotificationWithAttributedString:(NSAttributedString *)
                                                attributedString
                                    forDuration:(NSTimeInterval)duration;

/**
 * Displays a notification with the indicated custom view and then performs the
 * completion block once the notification animates in.
 * @param view
 *        The custom @c UIView that you wish to present.
 * @param completion
 *        The block to be invoked once the notification is displayed.
 */

- (void)displayNotificationWithView:(UIView *)view
                         completion:(void (^)(void))completion;

/**
 * Displays a notification with the indicated custom view for the indicated
 * duration.
 * @param view
 *        The custom @c UIView that you wish to present.
 * @param duration
 *        The amount of seconds for which the notification should be displayed,
 *        not including the animate in and out times.
 */
- (void)displayNotificationWithView:(UIView *)view
                        forDuration:(NSTimeInterval)duration;

/**
 * Dismisses the currently presented notification and then performs the
 * completion block.
 * @param completion
 *        The block to be invoked after the notification is dismissed.
 */
- (void)dismissNotificationWithCompletion:(void(^)(void))completion;

/**
 * Dismisses the currently presented notification.
 */

- (void)dismissNotification;

@end
