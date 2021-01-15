//
//  ViewsForIB.m
//  Electron-Cash
//
//  Created by calin on 4/7/18.
//  Copyright © 2018 Calin Culianu <calin.culiau@gmail.com>. MIT License.
//

#import "ViewsForIB.h"

#define DEGREES_TO_RADIANS(x) (M_PI * (x) / 180.0)


static BOOL IS_IPHONE_5(void) {
    static int isiPhone5 = -12345;

    if (isiPhone5 == -12345)
        isiPhone5 = (int)(( fabs( ( double )[ [ UIScreen mainScreen ] nativeBounds ].size.height - ( double )1136.0 ) < DBL_EPSILON ) && UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPhone);
    return (BOOL)isiPhone5;
}

static void applyWorkaround(UIViewController *vc) {
    if (@available(iOS 13, *)) {
        vc.modalPresentationStyle = UIModalPresentationFullScreen;
        NSLog(@"iOS 13+ workaround: forcing presentation style to fullscreen for %@", [vc description]);
    }
}

@implementation CustomViewController
- (id) init {
    self = [super init];
    applyWorkaround(self);
    return self;
}
- (id) initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    applyWorkaround(self);
    return self;
}
- (id) initWithCoder:(NSCoder *)coder {
    self = [super initWithCoder:coder];
    applyWorkaround(self);
    return self;
}
- (void)presentViewController:(UIViewController *)viewControllerToPresent
                     animated:(BOOL)flag
                   completion:(void (^)(void))completion {
    applyWorkaround(viewControllerToPresent);
    [super presentViewController:viewControllerToPresent animated:flag completion:completion];
}
@end

@implementation CustomNavController
- (id) init {
    self = [super init];
    applyWorkaround(self);
    return self;
}
- (id) initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    applyWorkaround(self);
    return self;
}
- (id) initWithCoder:(NSCoder *)coder {
    self = [super initWithCoder:coder];
    applyWorkaround(self);
    return self;
}
- (id) initWithRootViewController:(UIViewController *)rootViewController {
    self = [super initWithRootViewController:rootViewController];
    applyWorkaround(self);
    return self;
}
- (id) initWithNavigationBarClass:(Class)navigationBarClass toolbarClass:(Class)toolbarClass {
    self = [super initWithNavigationBarClass:navigationBarClass toolbarClass:toolbarClass];
    applyWorkaround(self);
    return self;
}
- (void)presentViewController:(UIViewController *)viewControllerToPresent
                     animated:(BOOL)flag
                   completion:(void (^)(void))completion {
    applyWorkaround(viewControllerToPresent);
    [super presentViewController:viewControllerToPresent animated:flag completion:completion];
}
@end

@implementation AddrConvBase
// properties get autosynthesized since Xcode 4.4
@end

@implementation NewContactBase
// properties will be auto-synthesized
-(BOOL) textFieldShouldReturn:(UITextField *)tf {
    [tf resignFirstResponder];
    return YES;
}
@end

@implementation SendBase
// properties auto-synthesized
@end

@implementation TxDetailBase
// properties auto-synthesized
@end

@implementation TxInputsOutputsTVCBase
@end

@implementation WalletsNavBase
// properties auto-synthesized
@end

@implementation WalletsVCBase
// properties auto-synthesized
@end


@implementation WalletsDrawerVCBase {
    BOOL isRotating;
}
// synthesized properties
-(void)closeAnimated:(BOOL)animated {

    CGRect frame = self.drawer.frame, frameBottom = self.drawerBottom.frame;
    frame.size.height = 63.0;
    frameBottom.size.height = 0.0;
    const BOOL rotateChevron = !self.chevron.animationImages.count;

    if (animated && !isRotating) {

        isRotating = YES;

        [UIView animateWithDuration:0.2 delay:0.0 options: UIViewAnimationOptionAllowUserInteraction |UIViewAnimationOptionCurveLinear animations:^{
            if (rotateChevron)
                self.chevron.transform = CGAffineTransformIdentity;
            self.drawer.frame = frame;
            self.drawerHeight.constant = 63.0;
            self.drawerBottom.frame = frameBottom;
            self.drawerBottom.hidden = YES;
        } completion:^(BOOL finished) {
            self->isRotating = NO;
            self.isOpen = NO;
            if (!rotateChevron)
                self.chevron.image = self.chevron.animationImages.lastObject;
        }];

    } else {
        [self.chevron.layer removeAllAnimations];
        if (rotateChevron)
            self.chevron.transform = CGAffineTransformIdentity;
        else
            self.chevron.image = self.chevron.animationImages.lastObject;
        self.drawer.frame = frame;
        self.drawerHeight.constant = 63.0;
        isRotating = NO;
        self.isOpen = NO;
        self.drawerBottom.hidden = YES;
        self.drawerBottom.frame = frameBottom;
    }
}

-(void)openAnimated:(BOOL)animated {

    CGRect frame = self.drawer.frame, frameBottom = self.drawerBottom.frame;
    frame.size.height = 300.0;
    frameBottom.size.height = 237.0;
    const BOOL rotateChevron = !self.chevron.animationImages.count;

    if (animated && !isRotating) {

        isRotating = YES;

        [UIView animateWithDuration:0.2 delay:0.0 options: UIViewAnimationOptionAllowUserInteraction |UIViewAnimationOptionCurveLinear animations:^{
            if (rotateChevron)
                self.chevron.transform = CGAffineTransformMakeRotation(DEGREES_TO_RADIANS(179.9f));
            self.drawerHeight.constant = frame.size.height;
            self.drawer.frame = frame;
            self.drawerBottom.frame = frameBottom;
        } completion:^(BOOL finished) {
            self->isRotating = NO;
            self.isOpen = YES;
            self.drawerBottom.hidden = NO;
            if (!rotateChevron)
                self.chevron.image = self.chevron.animationImages.lastObject;
        }];

    } else {
        [self.chevron.layer removeAllAnimations];
        if (rotateChevron)
            self.chevron.transform = CGAffineTransformMakeRotation(DEGREES_TO_RADIANS(179.9f));
        else
            self.chevron.image = self.chevron.animationImages.lastObject;
        self.drawerHeight.constant = frame.size.height;
        self.drawer.frame = frame;
        isRotating = NO;
        self.isOpen = YES;
        self.drawerBottom.hidden = NO;
        self.drawerBottom.frame = frameBottom;
    }
}

@end

@implementation TxHistoryHelperBase
// auto-sythesized properties
@end

@implementation TxHistoryCell
// auto-sythesized properties

- (void) dealloc {
    // this is required to make sure our KVO observing gets uninstalled!
    self.desc = nil;
}

- (void) setDesc:(UILabel *)desc {
    if (_desc == desc) return;
    if (_desc) {
        [_desc removeObserver:self forKeyPath:@"text"];
        [_desc removeObserver:self forKeyPath:@"attributedText"];
    }
    _desc = desc;
    if (_desc) {
        [_desc addObserver:self forKeyPath:@"text" options:NSKeyValueObservingOptionNew|NSKeyValueObservingOptionOld|NSKeyValueObservingOptionInitial  context:NULL];
        [_desc addObserver:self forKeyPath:@"attributedText" options:NSKeyValueObservingOptionNew|NSKeyValueObservingOptionOld|NSKeyValueObservingOptionInitial  context:NULL];
    }
}
- (void) polishLayout:(BOOL)isAttributed {
    CGFloat delta = (isAttributed ? _desc.attributedText.string : _desc.text).length > 0 ? 9.0 : 0.0;

    self.amtCS.constant = 17.0 - delta;
    self.amtTitCS.constant = 19.0 - delta;
    self.dateCS.constant = 18.0 - delta;
    self.descCS.constant = 0.0 + floor(delta/2.0);
    [self layoutIfNeeded];
}

- (void) observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary<NSKeyValueChangeKey,id> *)change context:(void *)context {
    BOOL isAttributed = [keyPath isEqualToString:@"attributedText"];
    if ( (isAttributed || [keyPath isEqualToString:@"text"]) && object == _desc) {
        [self polishLayout:isAttributed];
    }
}

@end

@implementation ReqTVDBase
// auto-synthesized properties generated by compiler here...
@end

@implementation RequestListCell
// auto-sythesized properties

- (void) dealloc {
    // this is required to make sure our KVO observing gets uninstalled!
    self.desc = nil;
}

- (void) setDesc:(UILabel *)desc {
    if (_desc == desc) return;
    if (_desc) {
        [_desc removeObserver:self forKeyPath:@"text"];
        [_desc removeObserver:self forKeyPath:@"attributedText"];
    }
    _desc = desc;
    if (_desc) {
        [_desc addObserver:self forKeyPath:@"text" options:NSKeyValueObservingOptionNew|NSKeyValueObservingOptionOld|NSKeyValueObservingOptionInitial  context:NULL];
        [_desc addObserver:self forKeyPath:@"attributedText" options:NSKeyValueObservingOptionNew|NSKeyValueObservingOptionOld|NSKeyValueObservingOptionInitial  context:NULL];
    }
}
- (void) polishLayout:(BOOL)isAttributed {
    CGFloat delta = (isAttributed ? _desc.attributedText.string : _desc.text).length > 0 ? 7.5 : 0.0;

    self.addressTitCS.constant = 21.0 - delta;
    [self layoutIfNeeded];
}

- (void) observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary<NSKeyValueChangeKey,id> *)change context:(void *)context {
    BOOL isAttributed = [keyPath isEqualToString:@"attributedText"];
    if ( (isAttributed || [keyPath isEqualToString:@"text"]) && object == _desc) {
        [self polishLayout:isAttributed];
    }
}
@end

@implementation ContactsVCBase
// auto synthesized properties
@end

@implementation ContactsCell
// auto synthesized properties
@end

@implementation ContactDetailVCBase
// auto synthesized properties
@end

@implementation AddressesVCBase
// auto synthesized properties
@end

@implementation AddressesCell
// auto synthesized properties
@end

@implementation AddressDetailBase
// auto synthesized properties
@end

@implementation CoinsCellSelectedBackgroundView
- (void) layoutSubviews {
    if (!_selBut || !_blueView) {
        NSLog(@"** Warning in %s:%d: _selBut or _blueView are nil!", __FILE__, __LINE__);
        return;
    }
    // this fixes an issue on iPhone X landscpae mode where the blue view didn't line up with the selectionButton
    CGRect f = [_selBut convertRect:_selBut.bounds toView:self];
    CGSize bsize = CGSizeMake(_blueView.layer.cornerRadius*2.0,_blueView.layer.cornerRadius*2.0);
    f.origin.x += (f.size.width-bsize.width)/2.0;
    f.origin.y += (f.size.height-bsize.height)/2.0;
    f.size = bsize;
    _blueView.frame = f;
}
@end

@implementation CoinsCell {
    __weak IBOutlet UIImageView *_chevron;
    __weak IBOutlet NSLayoutConstraint *_rightCS;
    __weak IBOutlet UIButton *_selectionButton;
    __weak IBOutlet UIView *_butTapArea, *_accTapArea;
}
- (BOOL) chevronHidden { return _chevron.highlighted; }
- (void) setChevronHidden:(BOOL)b {
    _chevron.highlighted = b;
    if (b) {
        _rightCS.constant = -8.0;
    } else {
        _rightCS.constant = 19.0;
    }
    _accTapArea.userInteractionEnabled = !b;
}

- (BOOL) buttonSelected { return _selectionButton.selected; }
- (void) setButtonSelected:(BOOL)b {
    _selectionButton.selected = b;
}
- (BOOL) buttonEnabled { return _selectionButton.enabled; }
- (void) setButtonEnabled:(BOOL)b {
    _selectionButton.enabled = b;
    _butTapArea.userInteractionEnabled = b;
    if (!b) _selectionButton.alpha = 0.5;
    else    _selectionButton.alpha = 1.0;
}
- (IBAction) onSelBut {
    self.buttonSelected = !self.buttonSelected;
    if (_onButton) _onButton(self);
}
- (IBAction) onAccessoryTap {
    if (_onAccessory) _onAccessory(self);
}
- (void) awakeFromNib {
    [super awakeFromNib];
    // set up the gesture recognizer for the 'address'
    UIGestureRecognizer *gr = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(onAccessoryTap)];
    [_accTapArea addGestureRecognizer:gr];

    gr = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(onSelBut)];
    [_butTapArea addGestureRecognizer:gr];
}
// auto synthesized properties
@end

@implementation CoinsDetailBase
// auto synthesized properties
@end

@implementation PleaseWaitVC
- (void) viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    self.activityIndicator.animating = YES;
}
- (void) viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    self.activityIndicator.animating = NO;
}
@end

@implementation NewWalletNavBase
- (UIInterfaceOrientationMask) supportedInterfaceOrientations { return UIInterfaceOrientationMaskPortrait; }
- (UIInterfaceOrientation) preferredInterfaceOrientationForPresentation { return UIInterfaceOrientationPortrait; }
- (BOOL) shouldAutorotate { return NO; }
@end

@implementation NewWalletVCBase
- (void) setNoPWCheck:(BOOL)b {
    if (!!b == !!_noPWCheck) return;
    _noPWCheck = b;
    NSArray<UIView *> * items = @[ _walletPw1Tit, _walletPw1, _walletPw2Tit, _walletPw2, _showHidePWBut, _touchId, _touchIdTit ];
    for (UIView *v in items) {
        v.hidden = b;
    }
}
@end

@implementation NewWalletSeedBase
@end

@implementation SuggestionButton
+ (instancetype) suggestionButtonWithText:(NSString *)text handler:(void(^)(UIControl *))handler {
    SuggestionButton *but = [SuggestionButton buttonWithType:UIButtonTypeSystem];
    [but setTitle:text forState:UIControlStateNormal];
    UIFont *font = [UIFont systemFontOfSize:23.0];
    but.titleLabel.font = font;
    //but.titleLabel.textColor = UIColor.blackColor;
    but.tintColor = UIColor.blackColor;
    but.titleLabel.adjustsFontSizeToFitWidth = YES;
    but.titleLabel.minimumScaleFactor = IS_IPHONE_5() ? 0.3 : 0.44;
    but.backgroundColor = UIColor.whiteColor;
    [but setTitleColor:UIColor.blackColor forState:UIControlStateNormal];
    UIEdgeInsets insets = IS_IPHONE_5() ? UIEdgeInsetsMake(2.5, 5.0, 2.5, 5.0) : UIEdgeInsetsMake(5.0, 10.0, 5.0, 10.0);
    but.titleEdgeInsets = insets;
    but.layer.cornerRadius = 4.0;
    but.layer.borderWidth = 2.0;
    but.layer.borderColor = [UIColor colorInDeviceRGBWithHexString:@"#cccccc"].CGColor;
    but.clipsToBounds = YES;
    if (handler) {
        [but handleControlEvent:UIControlEventPrimaryActionTriggered withBlock:handler];
    }
    // auto-size based on contents
    CGRect f = CGRectMake(0,0,100,42); // testing
    CGRect r = [text boundingRectWithSize:CGSizeMake(10000.0,f.size.height-insets.bottom-insets.top) options:0 attributes:@{NSFontAttributeName : font} context:nil];
    f.size = CGSizeMake(r.size.width+insets.left+insets.right, f.size.height);
    but.frame = f;
    return but;
}
@end

@implementation NewWalletMenuBase
// auto-synth properties
- (void) viewDidLoad {
    self.std.layer.borderColor = self.std.backgroundColor.CGColor;
    self.restore.layer.borderColor = UIColor.whiteColor.CGColor;
    self.imp.layer.borderColor = UIColor.whiteColor.CGColor;
    self.master.layer.borderColor = UIColor.whiteColor.CGColor;
}
- (IBAction) dismiss { [self.presentingViewController dismissViewControllerAnimated:YES completion:nil]; }
@end

@implementation Import1Base
@end

@implementation Import2Base
@end

@implementation ImportCell
@end

@implementation OnBoardingWizardBase
- (UIInterfaceOrientationMask) supportedInterfaceOrientations { return UIInterfaceOrientationMaskPortrait; }
- (UIInterfaceOrientation) preferredInterfaceOrientationForPresentation { return UIInterfaceOrientationPortrait; }
- (BOOL) shouldAutorotate { return NO; }
@end

@implementation OnBoardingPageBase
@end
@implementation OnBoardingMenuBase
@end

@implementation TxDetailInOutCell
@end

@implementation SpendFromCell
@end

@implementation PrivateKeyDialogBase
@end

@implementation SignDecryptBase
@end

@implementation ReceiveBase
@end

@implementation SeedDisplayBase
@end

@implementation CrashReporterNav
- (UIInterfaceOrientationMask) supportedInterfaceOrientations { return UIInterfaceOrientationMaskPortrait; }
- (UIInterfaceOrientation) preferredInterfaceOrientationForPresentation { return UIInterfaceOrientationPortrait; }
- (BOOL) shouldAutorotate { return NO; }
@end

@implementation CrashReporterBase
@end


