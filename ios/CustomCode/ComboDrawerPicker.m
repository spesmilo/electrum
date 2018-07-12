//
//  ComboDrawerPicker.m
//  Electron-Cash
//
//  Created by calin on 5/22/18.
//  Copyright © 2018 Calin Culianu <calin.culianu@gmail.com>.
//  MIT License
//

#import "ComboDrawerPicker.h"

#define DEGREES_TO_RADIANS(x) (M_PI * (x) / 180.0)

@implementation ComboDrawerPicker {
    BOOL _inInit, _initted, _isRotating;
    __strong NSMutableArray<UIImage *> *_chevronImages, *_chevronImagesReversed;
    __strong UIImage *_bluechk, *_blankimg;
    CGFloat _savedBottomHeight;
}

- (void) commonInit {
    if (_initted) return;
    _inInit = YES;
    if (!_colorTitle) self.colorTitle = UIColor.grayColor;
    if (!_colorTitle2) self.colorTitle2 = UIColor.blueColor;
    if (!_colorItems) self.colorItems = UIColor.blackColor;
    self.flushLeft = _flushLeft; // in case it was preset with key-value setup in XIB, redo setup for it
    _chevronImages = [NSMutableArray arrayWithCapacity:6];
    _chevronImagesReversed = [NSMutableArray arrayWithCapacity:6];
    for (int i = 0; i < 6; ++i) {
        [_chevronImages addObject:[UIImage imageNamed:[NSString stringWithFormat:@"chevron_0000%u",(unsigned)i]]];
        [_chevronImagesReversed insertObject:_chevronImages[i] atIndex:0];
    }
    _bluechk = [UIImage imageNamed:@"bluechk"];
    { // create the blank image
        CGSize size = _bluechk.size;
        UIGraphicsBeginImageContextWithOptions(size, NO, _bluechk.scale);
        [[UIColor clearColor] setFill];
        UIRectFill(CGRectMake(0, 0, size.width, size.height));
        _blankimg = UIGraphicsGetImageFromCurrentImageContext();
        UIGraphicsEndImageContext();
    }
    _chevron.animationImages = _chevronImages;
    _chevron.highlightedAnimationImages = _chevronImagesReversed;
    _chevron.highlightedImage = _chevronImagesReversed[0];
    _chevron.image = _chevronImages[0];
    if (!_topTitle) self.topTitle = @"Title";
    if (!_items) self.items = @[@"Item 1", @"Item 2", @"Item 3", @"Item 4"];
    _savedBottomHeight = _bottomHeightCS.constant;
    if (!_opened) {
        _bottomHeightCS.constant = 0;
    }
    _chevron.highlighted = _opened;
    _inInit = NO;
    _initted = YES;
}
- (void)viewDidLoad { [super viewDidLoad]; [self commonInit]; }
- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self redoTitle];
    [_tv reloadData];
}

// property getter
- (NSAttributedString *)attributedStringForTopTitle {
    if (_selection >= _items.count || _inInit)
        return [[NSAttributedString alloc] initWithString:@""];
    NSMutableAttributedString *ats =
    [[NSMutableAttributedString alloc] initWithString:_topTitle
                                           attributes:@{
                                                        NSFontAttributeName : [UIFont systemFontOfSize:12.0],
                                                        NSForegroundColorAttributeName : self.colorTitle
                                                        }
     ];
    [ats appendAttributedString:
     [[NSMutableAttributedString alloc] initWithString:[NSString stringWithFormat:@"  %@",_items[_selection]]
                                            attributes:@{
                                                         NSFontAttributeName : [UIFont systemFontOfSize:14.0 weight:UIFontWeightBold],
                                                         NSForegroundColorAttributeName : self.colorTitle2

                                                         }
      ]];

    return ats;
}

- (void) redoTitle {
    _titLbl.attributedText = self.attributedStringForTopTitle;
}
// property override
- (void) setTopTitle:(NSString *)topTitle {
    _topTitle = [topTitle copy];
    [self redoTitle];
}
- (void) setItems:(NSArray<NSString *> *)items {
    _items = [items copy];
    if (_selection >= _items.count)
        self.selection = 0; // implicitly calls redoTitle
    else
        [self redoTitle];
    if (!_inInit) [_tv reloadData];
}
- (void) setFlushLeft:(BOOL)flushLeft {
    _flushLeft = flushLeft;
    if (_flushLeft) {
        _lmarginCS.active = YES;
        _rmarginCS.active = NO;
    } else {
        _lmarginCS.active = NO;
        _rmarginCS.active = YES;
    }
}

- (void) setSelection:(NSUInteger)selection {
    if (_selection == selection || selection >= _items.count) return;
    _selection = selection;
    if (!_inInit) {
        [self redoTitle];
        [_tv reloadData];
    }
}

- (void) setColorItems:(UIColor *)colorItems {
    _colorItems = [colorItems copy];
    if (!_inInit) [_tv reloadData];
}

- (void) setColorTitle:(UIColor *)colorTitle {
    _colorTitle = [colorTitle copy];
    if (!_inInit) [self redoTitle];
}


- (void) setColorTitle2:(UIColor *)colorTitle2 {
    _colorTitle2 = [colorTitle2 copy];
    if (!_inInit) [self redoTitle];
}

- (void) setOpened:(BOOL)opened {
    if (!!_opened == !!opened) return;
    if (_initted) {
        if (opened) [self openAnimated:YES];
        else [self closeAnimated:YES];
    } else
        _opened = opened;
}

- (void) toggleOpen {
    self.opened = !_opened;
}

-(void)openAnimated:(BOOL)animated  {
    const BOOL rotateChevron = !_chevron.animationImages.count;

    _opened = YES;
    if (animated && !_isRotating) {

        _isRotating = YES;


        if (!rotateChevron) {
            _chevron.animationDuration = 0.2;
            _chevron.animationRepeatCount = 1;
            _chevron.highlighted = NO;
            [_chevron startAnimating];
            _chevron.image = _chevronImagesReversed[0]; // this forces the end of the animation to use the right image.. avoids a glitch on ios 10
        }

        [UIView animateWithDuration:0.2 delay:0.0 options: UIViewAnimationOptionAllowUserInteraction |UIViewAnimationOptionCurveLinear animations:^{
            if (rotateChevron)
                self->_chevron.transform = CGAffineTransformMakeRotation(DEGREES_TO_RADIANS(179.9f));
            CGRect frame = self->_bottomView.frame;
            frame.size.height = self->_savedBottomHeight;
            self->_bottomView.frame = frame;
        } completion:^(BOOL finished) {
            if (!rotateChevron) {
                [self->_chevron stopAnimating];
                self->_chevron.highlighted = YES;
                self->_chevron.image = self->_chevronImages[0]; // this forces the end of the animation to use the right image.. avoids a glitch on ios 10
            }
            self->_bottomHeightCS.constant = self->_savedBottomHeight;
            self->_isRotating = NO;
            self->_opened = YES;
            if (finished && self->_openClosedBlock) self->_openClosedBlock(YES);
        }];

    } else {
        if (rotateChevron) {
            [_chevron.layer removeAllAnimations];
            _chevron.transform = CGAffineTransformMakeRotation(DEGREES_TO_RADIANS(179.9f));
        } else {
            [_chevron stopAnimating];
            _chevron.highlighted = YES;
            _chevron.image = _chevronImages[0]; // this forces the end of the animation to use the right image.. avoids a glitch on ios 10
        }
        _bottomHeightCS.constant = _savedBottomHeight;
        _isRotating = NO;
        _opened = YES;
        if (_openClosedBlock) _openClosedBlock(YES);
    }
}

-(void)closeAnimated:(BOOL)animated {
    const BOOL rotateChevron = !_chevron.highlightedAnimationImages.count;

    _opened = NO;
    if (animated && !_isRotating) {

        _isRotating = YES;


        if (!rotateChevron) {
            _chevron.animationDuration = 0.2;
            _chevron.animationRepeatCount = 1;
            _chevron.highlighted = YES;
            [_chevron startAnimating];
            _chevron.highlightedImage = _chevronImages[0]; // this forces the end of the animation to use the right image.. avoids a glitch on ios 10
        }

        [UIView animateWithDuration:0.2 delay:0.0 options: UIViewAnimationOptionAllowUserInteraction |UIViewAnimationOptionCurveLinear animations:^{
            if (rotateChevron)
                self->_chevron.transform = CGAffineTransformIdentity;
            CGRect frame = self->_bottomView.frame;
            frame.size.height = 0;
            self->_bottomView.frame = frame;
            self->_bottomHeightCS.constant = 0.;
        } completion:^(BOOL finished) {
            if (!rotateChevron) {
                [self->_chevron stopAnimating];
                self->_chevron.highlighted = NO;
                self->_chevron.highlightedImage = self->_chevronImagesReversed[0]; // this forces the end of the animation to use the right image.. avoids a glitch on ios 10
            }
            self->_bottomHeightCS.constant = 0;
            self->_isRotating = NO;
            self->_opened = NO;
            if (finished && self->_openClosedBlock) self->_openClosedBlock(NO);
        }];

    } else {
        if (rotateChevron) {
            [_chevron.layer removeAllAnimations];
            _chevron.transform = CGAffineTransformIdentity;
        } else {
            [_chevron stopAnimating];
            _chevron.highlighted = NO;
            _chevron.highlightedImage = _chevronImagesReversed[0]; // this forces the end of the animation to use the right image.. avoids a glitch on ios 10
        }
        _bottomHeightCS.constant = 0;
        _isRotating = NO;
        _opened = NO;
        if (_openClosedBlock) _openClosedBlock(NO);
    }
}

- (NSInteger) numberOfSectionsInTableView:(UITableView *)tv { return 1; }
- (NSInteger) tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)section {
    return _inInit ? 0 : _items.count;
}
- (UITableViewCell *) tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tv dequeueReusableCellWithIdentifier:@"Cell"];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"Cell"];
    }
    if (indexPath.row < _items.count) {
        cell.textLabel.text = _items[indexPath.row];
        cell.textLabel.textColor = _colorItems;
        cell.textLabel.font = [UIFont systemFontOfSize:14.0];
        cell.imageView.image = indexPath.row == _selection ? _bluechk : _blankimg;
    }
    return cell;
}
- (void) tableView:(UITableView *)tv didSelectRowAtIndexPath:(nonnull NSIndexPath *)indexPath {
    [tv deselectRowAtIndexPath:indexPath animated:YES];
    // Delay 0.1 seconds so deselect animation can play, then select it
    __weak ComboDrawerPicker *weakSelf = self;
    const NSInteger sel = indexPath.row; // to not keep the indexPath object alive longer than we need to
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        weakSelf.selection = sel;
        if (weakSelf.selectedBlock) weakSelf.selectedBlock(sel);
    });
}
- (IBAction) tappedOutside:(UIGestureRecognizer *)gr {
    if (_backgroundTappedBlock) {
        CGPoint p = [gr locationInView:self.view];
        _backgroundTappedBlock(p);
    }
}
- (IBAction) tappedControl {
    if (_autoOpenCloseOnTap) [self toggleOpen];
    if (_controlTappedBlock) _controlTappedBlock();
}
@end
