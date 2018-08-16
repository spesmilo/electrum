//
//  ECTextViewDelegate.m
//  Electron-Cash
//
//  Created by calin on 5/25/18.
//  Copyright © 2018 Calin Culianu. MIT License.
//

#import "ECTextViewDelegate.h"

@implementation ECTextViewDelegate {
    BOOL _isPlaceholder;
    NSTextAlignment _savedAlignment;
}


- (void) setupAccessoryView {
    if (_tv && !_tv.inputAccessoryView) {
        UIBarButtonItem *item, *spacer;

        spacer = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace
                                                               target:nil
                                                               action:nil];
        item = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                             target:self
                                                             action:@selector(closeKeyboard)];
        UIToolbar *toolBar = [UIToolbar new];
        [toolBar sizeToFit];
        toolBar.items = @[spacer, item];
        _tv.inputAccessoryView = toolBar;
    }
}

- (NSAttributedString *) genAttrText:(NSString *) text {
    // nonempty string.. remove placeholder
    NSMutableDictionary *attrs = [NSMutableDictionary dictionaryWithDictionary:@{
                                                                                 NSFontAttributeName : _font,
                                                                                 NSForegroundColorAttributeName : _color
                                                                                 }];
    if (_centerPlaceholder) {
        NSMutableParagraphStyle *ps = [NSMutableParagraphStyle new];
        [ps setParagraphStyle: _paragraphStyle ? _paragraphStyle : [NSParagraphStyle defaultParagraphStyle]];
        [ps setAlignment:_savedAlignment];
        [attrs addEntriesFromDictionary:@{NSParagraphStyleAttributeName : ps}];
    } else if (_paragraphStyle) {
        [attrs addEntriesFromDictionary:@{NSParagraphStyleAttributeName : _paragraphStyle}];
    }
    return [[NSAttributedString alloc] initWithString:text attributes:attrs];
}

- (void) doPlaceholdifyIfNeeded:(BOOL)forceoff {
    if (_tv && !_text.length && _placeholderText.length && !_isPlaceholder) {
        // empty string.. put in placeholder
        NSMutableDictionary *attrs = [NSMutableDictionary dictionaryWithDictionary:@{
                                                                                     NSFontAttributeName : _placeholderFont,
                                                                                     NSForegroundColorAttributeName : _placeholderColor
                                                                                     }];
        if (_centerPlaceholder) {
            NSMutableParagraphStyle *ps = [NSMutableParagraphStyle new];
            [ps setParagraphStyle:[NSParagraphStyle defaultParagraphStyle]];
            [ps setAlignment:NSTextAlignmentCenter];
            [attrs addEntriesFromDictionary:@{NSParagraphStyleAttributeName : ps}];
        }
        _tv.attributedText = [[NSAttributedString alloc] initWithString:_placeholderText attributes:attrs];
        _isPlaceholder = YES;
    } else if (_tv && _isPlaceholder && (_text.length || forceoff)) {
        NSString *text = _text ? _text : @"";
        if (!text.length) {
            // if it's empty string, do it twice, first time with a space, to have the label "pick up" the attributes properly
            _tv.attributedText = [self genAttrText:@" "];
            _tv.attributedText = [self genAttrText:text];
        } else
            _tv.attributedText = [self genAttrText:text];
        _isPlaceholder = NO;
    }
}

- (void) setTv:(UITextView *)tv {
    if (_tv == tv) return;
    if (_tv) {
        _tv.delegate = nil;
        _tv.inputAccessoryView = nil;
    }
    _isPlaceholder = NO;
    _tv = tv;
    _tv.delegate = self;
    [self setupAccessoryView];
    if (_font) _tv.font = _font; else self.font = _tv.font;
    if (_color) _tv.textColor = _color; else self.color = _tv.textColor;
    if (!_placeholderFont) self.placeholderFont = _tv.font;
    if (!_placeholderColor) self.placeholderColor = _tv.textColor;
    _savedAlignment = _tv.textAlignment;
    self.text = _tv.text ? _tv.text : @""; // possibly re-set the text from the textView
}

- (void) setText:(NSString *)text {
    _text = _dontStrip ? [text copy] : [text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!_isPlaceholder) _tv.attributedText = [self genAttrText:_text];
    [self doPlaceholdifyIfNeeded:NO];
}

- (void) textViewDidBeginEditing:(UITextView *)textView {
    [self doPlaceholdifyIfNeeded:YES];
    if (_didEndEditing) _didBeginEditing();
}
- (void) textViewDidEndEditing:(UITextView *)textView {
    self.text = _tv.text; // calls doPlaceholdifyIfNeeded
    if (_didEndEditing) _didEndEditing(_text);
}
- (void) textViewDidChange:(UITextView *)textView {
    if (_didChange) _didChange();
}

- (void) closeKeyboard { [_tv endEditing:YES]; }
@end

