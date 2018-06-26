//
//  KeyboardVC.m
//  tskbd
//
//  Created by calin on 5/27/18.
//  Copyright © 2018 c3-soft.com. All rights reserved.
//

#import "KeyboardVC.h"
#import "../UIKitExtras.h"
#import "CYRKeyboardButton/CYRKeyboardButton.h"


static BOOL IS_IPHONE_5(void) {
    static int isiPhone5 = -12345;

    if (isiPhone5 == -12345)
        isiPhone5 = (int)(( fabs( ( double )[ [ UIScreen mainScreen ] nativeBounds ].size.height - ( double )1136.0 ) < DBL_EPSILON ) && UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPhone);
    return (BOOL)isiPhone5;
}

@interface FakeInputView()
@property (nonatomic, weak) UIView *mainView;
@property (nonatomic, weak) KeyboardVC *kbdvc;
- (void) setupMainView:(CGSize)size withVC:(KeyboardVC *)kbdvc;
@end

@interface KeyboardVC ()
@property (nonatomic, copy) void (^keyCallback)(NSString *key); ///< made this private since the default one is good enough.. no need to change it
@end

@implementation KeyboardVC {
    CGSize _keySize;
    NSMutableDictionary<NSString *, CYRKeyboardButton *> *_keyDict;
}
@synthesize keySize = _keySize;

+ (CGSize) preferredSize {
    static CGSize size =  {-1.,-1.};

    if (size.width < 0.0) {
        size = IS_IPHONE_5() ? CGSizeMake(365,112) : CGSizeMake(375,182);
        if ([UIDevice currentDevice].userInterfaceIdiom == UIUserInterfaceIdiomPad)
            size.height += 50;
    }
    return size;
}
- (instancetype) init {
    if (self = [super init]) {
        [self commonInit];
    }
    return self;
}
- (instancetype) initWithCoder:(NSCoder *)aDecoder {
    if (self = [super initWithCoder:aDecoder]) {
        [self commonInit];
    }
    return self;
}

- (void)encodeWithCoder:(nonnull NSCoder *)aCoder {
    [super encodeWithCoder:aCoder];
}

- (instancetype) initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    if (self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil]) {
        [self commonInit];
    }
    return self;
}

- (void) commonInit {
    self.vpad = IS_IPHONE_5() ? 3.0 : 12.0;
    self.hpad = IS_IPHONE_5() ? 6.0 : 6.0;
    self.hmargin = IS_IPHONE_5() ? 30.0 : 5.0;
    self.vmargin = IS_IPHONE_5() ? 4.0 : 13.0;
    self.blockPasting = YES;
    self.blockSelecting = YES;
    _keySize = IS_IPHONE_5() ? CGSizeMake(25.0, 33.0) : CGSizeMake(31.0,42.0);
    _backspace = @"⌫";
}

- (void)viewDidLoad {
    [super viewDidLoad];
    if (![self.view isKindOfClass:[FakeInputView class]]) {
        @throw [NSException exceptionWithName:@"NeedFakeInputView" reason:@"KeyboardVC's self.view must be a FakeInputView subclass!" userInfo:nil];
    }
    FakeInputView *fview = (FakeInputView *)self.view;
    CGSize psize = KeyboardVC.preferredSize;
    if (!fview.mainView) [fview setupMainView:psize withVC:self];
    // Do any additional setup after loading the view.
    const char *rows = !_lowerCase ? "QWERTYUIOP/-ASDFGHJKL/-=ZXCVBNM....<" : "qwertyuiop/-asdfghjkl/-=zxcvbnm....<",
               *c = rows;
    CGPoint p = CGPointMake(_hmargin,_vmargin);
    _keyDict = [[NSMutableDictionary alloc] initWithCapacity:26];
    // the below loop builds the keyboard layout using our custom syntax codes embedded in the above 'rows' string
    for (; *c; ++c) {
        if (*c == '/') {
            // 'next row', by defaults indents the row in by hmargin points
            p.x = _hmargin;
            p.y += _keySize.height + _vpad;
        } else if (*c == '-') {
            // indent further by half a key's width plus padding
            p.x += _keySize.width / 2.0 + _hpad;
        } else if (*c == '=') {
            // indent even more by a whole key plus padding
            p.x += _keySize.width + _hpad;
        } else if (*c == '.') {
            // tiny pad -- 1.0 points
            p.x += 1.0;
        } else {
            // actual key. crate the object and set its frame
            char ch = *c;
            BOOL keyRepeat = NO;
            CGRect frame = CGRectMake(p.x, p.y, _keySize.width, _keySize.height);
            UIColor *keyColor = UIColor.whiteColor;
            NSString *charAsString = [NSString stringWithFormat:@"%c", ch];
            UIFont *font = nil, *inputOptionsFont = nil;
            if (ch == '<') {
                frame.size = CGSizeMake(MAX(frame.size.width, frame.size.height), frame.size.height);
                keyColor = [UIColor colorInDeviceRGBWithHexString:@"#CCCCCC"];
                charAsString = _backspace;
                font = [UIFont fontWithName:@"HelveticaNeue-UltraLight" size:16.0];
                inputOptionsFont = [UIFont fontWithName:@"HelveticaNeue-UltraLight" size:22.0];
                keyRepeat = YES;
            }
            CYRKeyboardButton *key = [[CYRKeyboardButton alloc] initWithFrame:frame];
            key.translatesAutoresizingMaskIntoConstraints = NO;
            key.input = charAsString;
            __weak KeyboardVC *weakSelf = self;
            key.textInputCallback = ^(NSString *text) { [weakSelf gotAKey:text]; };
            key.keyShadowColor = keyColor;
            key.keyColor = keyColor;
            key.keyRepeat = keyRepeat;
            key.style = CYRKeyboardButtonStylePhone;
            if (font) key.font = font;
            if (inputOptionsFont) key.inputOptionsFont = inputOptionsFont;
            [fview.mainView addSubview:key];
            p.x += _keySize.width + _hpad;
            _keyDict[charAsString] = key;
        }
    }
}

- (NSArray<NSString *> *) allKeys {
    NSArray<NSString *> *ret = _keyDict.allKeys;
    return ret;
}

- (NSArray<NSString *> *)disabledKeys {
    NSMutableArray<NSString *> *ret = [NSMutableArray new];
    [_keyDict enumerateKeysAndObjectsUsingBlock:^(NSString *key, CYRKeyboardButton *val, BOOL* stop) {
        if (!val.userInteractionEnabled) [ret addObject:key];
    }];
    return ret;
}

- (void) keyEnablerDisabler:(BOOL)disabled {
    NSArray<NSString *> *ks = self.allKeys;
    for (NSString *k in ks) {
        [self setKey:k disabled:disabled];
    }
}

- (void) disableAllKeys {  [self keyEnablerDisabler:YES]; }
- (void) enableAllKeys {  [self keyEnablerDisabler:NO]; }

-(void) setupDefaultCallback {
    if (!_keyCallback) {
        __weak KeyboardVC *weakSelf = self;
        self.keyCallback = ^(NSString *k) {
            if ([weakSelf.textInput respondsToSelector:@selector(isFirstResponder)] && ![((id)weakSelf.textInput) isFirstResponder])
                return;
            if (weakSelf.blockSelecting && [weakSelf.textInput respondsToSelector:@selector(selectedRange)]) {
                // force insert at end
                UITextView *tv = (UITextView *)weakSelf.textInput;
                NSRange r = tv.selectedRange;
                if (r.location != tv.text.length || r.length != 0)
                    tv.selectedRange = NSMakeRange(tv.text.length, 0);
            }

            if ([k isEqualToString:weakSelf.backspace]) {
                [weakSelf.textInput deleteBackward];
            } else {
                if (weakSelf.lowerCaseInsert) k = [k lowercaseString];
                [weakSelf.textInput insertText:k];
            }
            if (weakSelf.textChanged) weakSelf.textChanged();
        };
    }
}

- (void) setTextInput:(id<UITextInput>)textInput {
    _textInput = textInput;
    if ([_textInput isKindOfClass:[UITextField class]] || [_textInput isKindOfClass:[UITextView class]]) {
        [((id)_textInput) setDelegate:self];
        [((id)_textInput) setInputView:[FakeInputView fakeInputView]];
        [self setupDefaultCallback];
    }
}

- (BOOL) isKeyDisabled:(NSString *)key {
    return _keyDict[key].alpha < 0.66; // we have to check on alpha as we now support user interaction on pseudo-disabled keys
}

- (void) setKey:(NSString *)key disabled:(BOOL)disabled {
    _keyDict[key].userInteractionEnabled = !disabled || _disabledKeysStillAcceptTouches;
    _keyDict[key].alpha = disabled ? 0.4 : 1.0;
}

- (void) setDisabledKeysStillAcceptTouches:(BOOL)b {
    if (!!b == !!_disabledKeysStillAcceptTouches) return;
    _disabledKeysStillAcceptTouches = b;
    NSArray<NSString *> *ak = self.allKeys;
    for (NSString *k in ak) {
        // redo it now that we got a new value
        [self setKey:k disabled:[self isKeyDisabled:k]];
    }
}

- (void) setKey:(NSString *)key enabled:(BOOL)enabled {
    [self setKey:key disabled:!enabled];
}

- (void) loadView {
    [super loadView];
    self.view = [[FakeInputView alloc] initWithFrame:CGRectMake(0.0,0.0,KeyboardVC.preferredSize.width, KeyboardVC.preferredSize.height)];
    self.view.opaque = NO;
    self.view.backgroundColor = [UIColor colorInDeviceRGBWithHexString:@"#DFDFDF"];
    self.view.autoresizesSubviews = NO;
    self.view.autoresizingMask = UIViewAutoresizingNone;
}

- (void) gotAKey:(NSString *)text {
    if (_keyCallback) _keyCallback(text);
    //NSLog(@"key: %@", text);
}

- (BOOL)textView:(UITextView *)textView shouldChangeTextInRange:(NSRange)range replacementText:(NSString *)text {
    return text.length && self.blockPasting ? NO : YES;; //  prevent pasting of text!
}

- (BOOL)textField:(UITextField *)textField shouldChangeCharactersInRange:(NSRange)range replacementString:(NSString *)text {
    return text.length && self.blockPasting ? NO : YES;
}

- (void)textViewDidChangeSelection:(UITextView *)tv {
    if (_blockSelecting && (tv.selectedRange.length || tv.selectedRange.location != tv.text.length)) {
        tv.selectedRange = NSMakeRange(tv.text.length, 0);
    }
}
@end

@implementation FakeInputView
// this is required to get the clicks working..
- (BOOL) enableInputClicksWhenVisible { return YES; }

+ (instancetype) fakeInputView {
    FakeInputView * ret = [[FakeInputView alloc] initWithFrame:CGRectMake(0,0,1,1)];
    ret.backgroundColor = UIColor.clearColor;
    ret.userInteractionEnabled = NO;
    return ret;
}

- (void) setupMainView:(CGSize)size  withVC:(KeyboardVC *)vc {
    if (_mainView) [_mainView removeFromSuperview];
    UIView *strong = [[UIView alloc] initWithFrame:CGRectMake(0,0,size.width,size.height)];
    self.mainView = strong;
    self.kbdvc = vc;
    _mainView.backgroundColor = UIColor.clearColor;
    _mainView.autoresizingMask = /*UIViewAutoresizingFlexibleTopMargin|*/UIViewAutoresizingFlexibleLeftMargin|UIViewAutoresizingFlexibleRightMargin|UIViewAutoresizingFlexibleBottomMargin;
    _mainView.autoresizesSubviews = NO;
    self.autoresizesSubviews = YES;
    _mainView.opaque = NO;
    [self addSubview:_mainView];
}
@end

