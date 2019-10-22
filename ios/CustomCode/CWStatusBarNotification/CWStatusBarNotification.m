//
//  CWStatusBarNotification.m
//  CWNotificationDemo
//
//  Created by Cezary Wojcik on 11/15/13.
//  Copyright (c) 2015 Cezary Wojcik. MIT License.
//

#import <QuartzCore/QuartzCore.h>
#import "CWStatusBarNotification.h"

#define SYSTEM_VERSION_LESS_THAN(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)

#define FONT_SIZE 12.0f
#define PADDING 10.0f
#define SCROLL_SPEED 40.0f
#define SCROLL_DELAY 1.0f

static BOOL IS_IPHONEX() {
    static const CGSize XSizes[] = {
        { 1125.0, 2436.0 }, // iPhone X & iPhone XS
        {  828.0, 1792.0 }, // iPhone XR
        { 1242.0, 2688.0 }, // iPhone XS Max
    };
    static const int N = sizeof(XSizes)/sizeof(XSizes[0]);

    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPhone) {
        CGSize size = UIScreen.mainScreen.nativeBounds.size;
        for (int i = 0; i < N; ++i) {
            if (fabs(XSizes[i].width - size.width) < 0.5 && fabs(XSizes[i].height - size.height) < 0.5)
                return YES;
        }
    }
    return NO;
}

# pragma mark - ScrollLabel

@interface ScrollLabel ()
@property (nonatomic) BOOL alignBottom;
@end

@implementation ScrollLabel
{
    UIImageView *textImage;
}

- (id)initWithFrame:(CGRect)frame
{
    self = [super initWithFrame:frame];
    if (self) {
        textImage = [[UIImageView alloc] init];
        [self addSubview:textImage];
    }
    return self;
}

- (CGFloat)fullWidth
{
    return [self.text sizeWithAttributes:@{NSFontAttributeName: self.font}].width;
}

- (CGFloat)scrollOffset
{
    if (self.numberOfLines != 1) return 0;
    
    CGRect insetRect = CGRectInset(self.bounds, PADDING, 0);
    return MAX(0, [self fullWidth] - insetRect.size.width);
}

- (CGFloat)scrollTime
{
    return ([self scrollOffset] > 0) ? [self scrollOffset] / SCROLL_SPEED + SCROLL_DELAY : 0;
}

- (void)drawTextInRect:(CGRect)rect
{
    if ([self scrollOffset] > 0) {
        rect.size.width = [self fullWidth] + PADDING * 2;
        UIGraphicsBeginImageContextWithOptions(rect.size, NO, [UIScreen mainScreen].scale);
        [super drawTextInRect:rect];
        textImage.image = UIGraphicsGetImageFromCurrentImageContext();
        UIGraphicsEndImageContext();
        [textImage sizeToFit];
        [UIView animateWithDuration:[self scrollTime] - SCROLL_DELAY
                              delay:SCROLL_DELAY
                            options:UIViewAnimationOptionBeginFromCurrentState | UIViewAnimationOptionCurveEaseInOut
                         animations:^{
                             self->textImage.transform = CGAffineTransformMakeTranslation(-[self scrollOffset], 0);
                         } completion:^(BOOL finished) {
                         }];
    } else {
        textImage.image = nil;
        if (!_alignBottom)
            [super drawTextInRect:CGRectInset(rect, PADDING, 0)];
        else {
            CGFloat height = [self sizeThatFits:rect.size].height;

            rect.origin.y += rect.size.height - height;
            rect.size.height = height;
            [super drawTextInRect:CGRectInset(rect, PADDING, 0)];
        }
    }
}

@end

# pragma mark - CWWindowContainer

@implementation CWWindowContainer

- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event
{
    CGFloat height;
    if (SYSTEM_VERSION_LESS_THAN(@"8.0") && UIInterfaceOrientationIsLandscape([UIApplication sharedApplication].statusBarOrientation)) {
        height = [UIApplication sharedApplication].statusBarFrame.size.width;
    } else {
        height = [UIApplication sharedApplication].statusBarFrame.size.height;
    }
    if (point.y > 0 && point.y < (self.notificationHeight != 0.0 ? self.notificationHeight : height)) {
        return [super hitTest:point withEvent:event];
    }

    return nil;
}

@end

# pragma mark - CWViewController

@interface CWViewController()

@property (nonatomic, assign) NSInteger _cwViewControllerSupportedInterfaceOrientation;

@end

@implementation CWViewController

@synthesize preferredStatusBarStyle = _preferredStatusBarStyle;

- (UIStatusBarStyle)preferredStatusBarStyle
{
    return _preferredStatusBarStyle;
}

- (void)setSupportedInterfaceOrientations:(UIInterfaceOrientationMask)supportedInterfaceOrientations
{
    self._cwViewControllerSupportedInterfaceOrientation = supportedInterfaceOrientations;
}

- (UIInterfaceOrientationMask)supportedInterfaceOrientations
{
    return self._cwViewControllerSupportedInterfaceOrientation;
}

- (BOOL)prefersStatusBarHidden
{
    CGFloat statusBarHeight = [[UIApplication sharedApplication] statusBarFrame].size.height;
    return !(statusBarHeight > 0);
}

@end

# pragma mark - dispatch after with cancellation
// adapted from: https://github.com/Spaceman-Labs/Dispatch-Cancel

typedef void(^CWDelayedBlockHandle)(BOOL cancel);

static CWDelayedBlockHandle perform_block_after_delay(CGFloat seconds, dispatch_block_t block)
{
	if (block == nil) {
		return nil;
	}

	__block dispatch_block_t blockToExecute = [block copy];
	__block CWDelayedBlockHandle delayHandleCopy = nil;

	CWDelayedBlockHandle delayHandle = ^(BOOL cancel){
		if (NO == cancel && nil != blockToExecute) {
			dispatch_async(dispatch_get_main_queue(), blockToExecute);
		}

		blockToExecute = nil;
		delayHandleCopy = nil;
	};

	delayHandleCopy = [delayHandle copy];

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, seconds * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
		if (nil != delayHandleCopy) {
			delayHandleCopy(NO);
		}
	});

	return delayHandleCopy;
};

static void cancel_delayed_block(CWDelayedBlockHandle delayedHandle)
{
	if (delayedHandle == nil) {
		return;
	}

	delayedHandle(YES);
}
# pragma mark - CWStatusBarNotification

@interface CWStatusBarNotification()

@property (strong, nonatomic) UITapGestureRecognizer *tapGestureRecognizer;
@property (strong, nonatomic) CWDelayedBlockHandle dismissHandle;
@property (assign, nonatomic) BOOL isCustomView;

@end

@implementation CWStatusBarNotification

@synthesize notificationLabel, notificationLabelBackgroundColor, notificationLabelTextColor, notificationLabelFont, notificationWindow, customView;

@synthesize statusBarView;

@synthesize notificationStyle, notificationIsShowing;

- (CWStatusBarNotification *)init
{
    self = [super init];
    if (self) {
        // set default
        if ([[[UIApplication sharedApplication] delegate] respondsToSelector:@selector(window)]) {
            self.notificationLabelBackgroundColor = [[UIApplication sharedApplication] delegate].window.tintColor;
        } else {
            self.notificationLabelBackgroundColor = [UIColor blackColor];
        }
        self.notificationLabelTextColor = [UIColor whiteColor];
        self.notificationLabelFont = [UIFont systemFontOfSize:FONT_SIZE];
        self.notificationLabelHeight = 0.0;
        self.customView = nil;
        self.multiline = NO;
        self.supportedInterfaceOrientations = [UIApplication sharedApplication].keyWindow.rootViewController.supportedInterfaceOrientations;
        self.notificationAnimationDuration = 0.25;
        self.notificationStyle = CWNotificationStyleStatusBarNotification;
        self.notificationAnimationInStyle = CWNotificationAnimationStyleBottom;
        self.notificationAnimationOutStyle = CWNotificationAnimationStyleBottom;
        self.notificationAnimationType = CWNotificationAnimationTypeReplace;
        self.notificationIsDismissing = NO;
        self.isCustomView = NO;
        self.preferredStatusBarStyle = UIStatusBarStyleDefault;

        // create tap recognizer
        self.tapGestureRecognizer = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(notificationTapped:)];
        self.tapGestureRecognizer.numberOfTapsRequired = 1;

        // create default tap block
        __weak typeof(self) weakSelf = self;
        self.notificationTappedBlock = ^(void) {
            if (!weakSelf.notificationIsDismissing) {
                [weakSelf dismissNotification];
            }
        };
    }
    return self;
}

# pragma mark - dimensions

- (CGFloat)getStatusBarHeight
{
    if (self.notificationLabelHeight > 0) {
        return self.notificationLabelHeight;
    }
    CGFloat statusBarHeight = [[UIApplication sharedApplication] statusBarFrame].size.height;
    if (SYSTEM_VERSION_LESS_THAN(@"8.0") && UIInterfaceOrientationIsLandscape([UIApplication sharedApplication].statusBarOrientation)) {
        statusBarHeight = [[UIApplication sharedApplication] statusBarFrame].size.width;
    }
    if (IS_IPHONEX())
        statusBarHeight = 50.0; //20.0; // hack for iPhoneX
    return statusBarHeight > 0 ? statusBarHeight : 20;
}

- (CGFloat)getStatusBarWidth
{
    if (SYSTEM_VERSION_LESS_THAN(@"8.0") && UIInterfaceOrientationIsLandscape([UIApplication sharedApplication].statusBarOrientation)) {
        return [UIScreen mainScreen].bounds.size.height;
    }
    return [[UIApplication sharedApplication] keyWindow].bounds.size.width;
}

- (CGFloat)getStatusBarOffset
{
    if (IS_IPHONEX())
        return 0.0; //30.0; // hack for iPhoneX
    if ([self getStatusBarHeight] == 40.0f) {
        return -20.0f;
    }
    return 0.0f;
}

- (CGFloat)getNavigationBarHeight
{
    if (UIInterfaceOrientationIsPortrait([UIApplication sharedApplication].statusBarOrientation) ||
        UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        return 44.0f;
    }
    return 30.0f;
}

- (CGFloat)getNotificationLabelHeight
{
    switch (self.notificationStyle) {
        case CWNotificationStyleStatusBarNotification:
            return [self getStatusBarHeight];
        case CWNotificationStyleNavigationBarNotification:
            return [self getStatusBarHeight] + [self getNavigationBarHeight];
        default:
            return [self getStatusBarHeight];
    }
}

- (CGRect)getNotificationLabelTopFrame
{
    return CGRectMake(0, [self getStatusBarOffset] + -1*[self getNotificationLabelHeight], [self getStatusBarWidth], [self getNotificationLabelHeight]);
}

- (CGRect)getNotificationLabelLeftFrame
{
    return CGRectMake(-1*[self getStatusBarWidth], [self getStatusBarOffset], [self getStatusBarWidth], [self getNotificationLabelHeight]);
}

- (CGRect)getNotificationLabelRightFrame
{
    return CGRectMake([self getStatusBarWidth], [self getStatusBarOffset], [self getStatusBarWidth], [self getNotificationLabelHeight]);
}

- (CGRect)getNotificationLabelBottomFrame
{
    return CGRectMake(0, [self getStatusBarOffset] + [self getNotificationLabelHeight], [self getStatusBarWidth], 0);
}

- (CGRect)getNotificationLabelFrame
{
    return CGRectMake(0, [self getStatusBarOffset], [self getStatusBarWidth], [self getNotificationLabelHeight]);
}

# pragma mark - screen orientation change

- (void)updateStatusBarFrame
{
    UIView *view = self.isCustomView ? self.customView : self.notificationLabel;
    view.frame = [self getNotificationLabelFrame];
    self.statusBarView.hidden = YES;
}

# pragma mark - on tap

- (void)notificationTapped:(UITapGestureRecognizer*)recognizer
{
    [self.notificationTappedBlock invoke];
}

# pragma mark - display helpers

- (void)setupNotificationView:(UIView *)view
{
    view.clipsToBounds = YES;
    view.userInteractionEnabled = YES;
    [view addGestureRecognizer:self.tapGestureRecognizer];
    switch (self.notificationAnimationInStyle) {
        case CWNotificationAnimationStyleTop:
            view.frame = [self getNotificationLabelTopFrame];
            break;
        case CWNotificationAnimationStyleBottom:
            view.frame = [self getNotificationLabelBottomFrame];
            break;
        case CWNotificationAnimationStyleLeft:
            view.frame = [self getNotificationLabelLeftFrame];
            break;
        case CWNotificationAnimationStyleRight:
            view.frame = [self getNotificationLabelRightFrame];
            break;
    }
}

- (void)createNotificationLabelWithMessage:(NSString *)message
{
    self.notificationLabel = [ScrollLabel new];
    self.notificationLabel.numberOfLines = self.multiline ? 0 : 1;
    self.notificationLabel.text = message;
    self.notificationLabel.textAlignment = NSTextAlignmentCenter;
    self.notificationLabel.adjustsFontSizeToFitWidth = NO;
    self.notificationLabel.font = self.notificationLabelFont;
    self.notificationLabel.backgroundColor = self.notificationLabelBackgroundColor;
    self.notificationLabel.textColor = self.notificationLabelTextColor;
    if (self.notificationStyle == CWNotificationStyleStatusBarNotification && IS_IPHONEX())
        self.notificationLabel.alignBottom = YES;
    [self setupNotificationView:self.notificationLabel];
}

- (void)createNotificationCustomView:(UIView *)view
{
    self.customView = [[UIView alloc] init];
    // Doesn't use autoresizing masks so that we can create constraints below manually
    [view setTranslatesAutoresizingMaskIntoConstraints:NO];
    [self.customView addSubview:view];

    // Setup Auto Layout constaints so that the custom view that is added is consrtained to be the same
    // size as its superview, whose frame will be altered
    [self.customView addConstraint:[NSLayoutConstraint constraintWithItem:view attribute:NSLayoutAttributeTrailing relatedBy:NSLayoutRelationEqual toItem:self.customView attribute:NSLayoutAttributeTrailing multiplier:1.0 constant:0.0]];
    [self.customView addConstraint:[NSLayoutConstraint constraintWithItem:view attribute:NSLayoutAttributeLeading relatedBy:NSLayoutRelationEqual toItem:self.customView attribute:NSLayoutAttributeLeading multiplier:1.0 constant:0.0]];
    [self.customView addConstraint:[NSLayoutConstraint constraintWithItem:view attribute:NSLayoutAttributeTop relatedBy:NSLayoutRelationEqual toItem:self.customView attribute:NSLayoutAttributeTop multiplier:1.0 constant:0.0]];
    [self.customView addConstraint:[NSLayoutConstraint constraintWithItem:view attribute:NSLayoutAttributeBottom relatedBy:NSLayoutRelationEqual toItem:self.customView attribute:NSLayoutAttributeBottom multiplier:1.0 constant:0.0]];

    [self setupNotificationView:self.customView];
}

- (void)createNotificationWindow
{
    self.notificationWindow = [[CWWindowContainer alloc] initWithFrame:[[[UIApplication sharedApplication] keyWindow] bounds]];
    self.notificationWindow.backgroundColor = [UIColor clearColor];
    self.notificationWindow.userInteractionEnabled = YES;
    self.notificationWindow.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.notificationWindow.windowLevel = UIWindowLevelStatusBar;
    CWViewController *rootViewController = [[CWViewController alloc] init];
    [rootViewController setSupportedInterfaceOrientations:self.supportedInterfaceOrientations];
    rootViewController.preferredStatusBarStyle = self.preferredStatusBarStyle;
    self.notificationWindow.rootViewController = rootViewController;
    self.notificationWindow.notificationHeight = [self getNotificationLabelHeight];
}

- (void)createStatusBarView
{
    self.statusBarView = [[UIView alloc] initWithFrame:[self getNotificationLabelFrame]];
    self.statusBarView.clipsToBounds = YES;
    if (self.notificationAnimationType == CWNotificationAnimationTypeReplace) {
        UIView *statusBarImageView = [[UIScreen mainScreen] snapshotViewAfterScreenUpdates:YES];
        [self.statusBarView addSubview:statusBarImageView];
    }
    [self.notificationWindow.rootViewController.view addSubview:self.statusBarView];
    [self.notificationWindow.rootViewController.view sendSubviewToBack:self.statusBarView];
}

# pragma mark - frame changing

- (void)firstFrameChange
{
    UIView *view = self.isCustomView ? self.customView : self.notificationLabel;
    view.frame = [self getNotificationLabelFrame];
    switch (self.notificationAnimationInStyle) {
        case CWNotificationAnimationStyleTop:
            self.statusBarView.frame = [self getNotificationLabelBottomFrame];
            break;
        case CWNotificationAnimationStyleBottom:
            self.statusBarView.frame = [self getNotificationLabelTopFrame];
            break;
        case CWNotificationAnimationStyleLeft:
            self.statusBarView.frame = [self getNotificationLabelRightFrame];
            break;
        case CWNotificationAnimationStyleRight:
            self.statusBarView.frame = [self getNotificationLabelLeftFrame];
            break;
    }
}

- (void)secondFrameChange
{
    UIView *view = self.isCustomView ? self.customView : self.notificationLabel;
    switch (self.notificationAnimationOutStyle) {
        case CWNotificationAnimationStyleTop:
            self.statusBarView.frame = [self getNotificationLabelBottomFrame];
            break;
        case CWNotificationAnimationStyleBottom:
            self.statusBarView.frame = [self getNotificationLabelTopFrame];
            view.layer.anchorPoint = CGPointMake(0.5f, 1.0f);
            view.center = CGPointMake(view.center.x, [self getStatusBarOffset] + [self getNotificationLabelHeight]);
            break;
        case CWNotificationAnimationStyleLeft:
            self.statusBarView.frame = [self getNotificationLabelRightFrame];
            break;
        case CWNotificationAnimationStyleRight:
            self.statusBarView.frame = [self getNotificationLabelLeftFrame];
            break;
    }
}

- (void)thirdFrameChange
{
    UIView *view = self.isCustomView ? self.customView : self.notificationLabel;
    self.statusBarView.frame = [self getNotificationLabelFrame];
    switch (self.notificationAnimationOutStyle) {
        case CWNotificationAnimationStyleTop:
            view.frame = [self getNotificationLabelTopFrame];
            break;
        case CWNotificationAnimationStyleBottom:
            view.transform = CGAffineTransformMakeScale(1.0f, 0.01f);
            break;
        case CWNotificationAnimationStyleLeft:
            view.frame = [self getNotificationLabelLeftFrame];
            break;
        case CWNotificationAnimationStyleRight:
            view.frame = [self getNotificationLabelRightFrame];
            break;
    }
}

# pragma mark - display notification

- (void)displayNotificationWithMessage:(NSString *)message completion:(void (^)(void))completion
{
    if (!self.notificationIsShowing) {
        self.isCustomView = NO;
        self.notificationIsShowing = YES;

        // create UIWindow
        [self createNotificationWindow];

        // create ScrollLabel
        [self createNotificationLabelWithMessage:message];

        // create status bar view
        [self createStatusBarView];

        // add label to window
        [self.notificationWindow.rootViewController.view addSubview:self.notificationLabel];
        [self.notificationWindow.rootViewController.view bringSubviewToFront:self.notificationLabel];
        [self.notificationWindow setHidden:NO];

        // checking for screen orientation change
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(updateStatusBarFrame) name:UIApplicationDidChangeStatusBarOrientationNotification object:nil];

        // checking for status bar change
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(updateStatusBarFrame) name:UIApplicationWillChangeStatusBarFrameNotification object:nil];

        // animate
        [UIView animateWithDuration:self.notificationAnimationDuration animations:^{
            [self firstFrameChange];
        } completion:^(BOOL finished) {
            double delayInSeconds = [self.notificationLabel scrollTime];
            perform_block_after_delay(delayInSeconds, ^{
                [completion invoke];
            });
        }];
    }
}

- (void)displayNotificationWithMessage:(NSString *)message forDuration:(NSTimeInterval)duration
                   dismissedCompletion:(void (^)(void))dismissedCompletion
{
    [self displayNotificationWithMessage:message completion:^{
        self.dismissHandle = perform_block_after_delay(duration, ^{
            [self dismissNotificationWithCompletion:dismissedCompletion];
        });
    }];
}

- (void)displayNotificationWithMessage:(NSString *)message forDuration:(NSTimeInterval)duration
{
    [self displayNotificationWithMessage:message forDuration:duration dismissedCompletion:nil];
}



- (void)displayNotificationWithAttributedString:(NSAttributedString *)attributedString completion:(void (^)(void))completion
{
    [self displayNotificationWithMessage:[attributedString string] completion:completion];
    [[self notificationLabel] setAttributedText:attributedString];
}

- (void)displayNotificationWithAttributedString:(NSAttributedString *)attributedString forDuration:(NSTimeInterval)duration
{
    [self displayNotificationWithMessage:[attributedString string] forDuration:duration];
    [[self notificationLabel] setAttributedText:attributedString];
}

- (void)displayNotificationWithView:(UIView *)view completion:(void (^)(void))completion
{
    if (!self.notificationIsShowing) {
        self.isCustomView = YES;
        self.notificationIsShowing = YES;

        // create window
        [self createNotificationWindow];

        // setup view
        [self createNotificationCustomView:view];

        // create status bar view
        [self createStatusBarView];

        // add view to window
        UIView *rootView = self.notificationWindow.rootViewController.view;
        [rootView addSubview:self.customView];
        [rootView bringSubviewToFront:self.customView];
        [self.notificationWindow setHidden:NO];

        // checking for screen orientation change
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(updateStatusBarFrame) name:UIApplicationDidChangeStatusBarOrientationNotification object:nil];

        // checking for status bar change
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(updateStatusBarFrame) name:UIApplicationWillChangeStatusBarFrameNotification object:nil];

        // animate
        [UIView animateWithDuration:self.notificationAnimationDuration animations:^{
            [self firstFrameChange];
        } completion:^(BOOL finished) {
            [completion invoke];
        }];
    }
}

- (void)displayNotificationWithView:(UIView *)view forDuration:(NSTimeInterval)duration
{
    [self displayNotificationWithView:view completion:^{
        self.dismissHandle = perform_block_after_delay(duration, ^{
            [self dismissNotification];
        });
    }];
}

- (void)dismissNotificationWithCompletion:(void (^)(void))completion
{
    if (self.notificationIsShowing) {
        cancel_delayed_block(self.dismissHandle);
        self.notificationIsDismissing = YES;
        [self secondFrameChange];
        [UIView animateWithDuration:self.notificationAnimationDuration animations:^{
            [self thirdFrameChange];
        } completion:^(BOOL finished) {
            UIView *view = self.isCustomView ? self.customView : self.notificationLabel;
            [view removeFromSuperview];
            [self.statusBarView removeFromSuperview];
            [self.notificationWindow setHidden:YES];
            self.notificationWindow = nil;
            view = nil;
            self.notificationIsShowing = NO;
            self.notificationIsDismissing = NO;
            [[NSNotificationCenter defaultCenter] removeObserver:self name:UIApplicationDidChangeStatusBarOrientationNotification object:nil];
            [[NSNotificationCenter defaultCenter] removeObserver:self name:UIApplicationWillChangeStatusBarFrameNotification object:nil];
            if (completion) {
                completion();
            }
        }];
    } else {
        if (completion) {
            completion();
        }
    }
}

- (void)dismissNotification
{
    [self dismissNotificationWithCompletion:nil];
}
@end
