//
//  UIScrollView+DZNSegmentedControl.m
//  DZNSegmentedControl
//  https://github.com/dzenbot/DZNSegmentedControl
//
//  Created by Ignacio Romero Zurbuchen on 1/26/15.
//  Copyright (c) 2014 DZN Labs. All rights reserved.
//  Licence: MIT-Licence
//

#import "DZNSegmentedControl.h"
#import <objc/runtime.h>

const char * segmentedControlKey;
const char * scrollDirectionKey;
const char * scrollOnSegmentChangeKey;

const char * observerContext;

static NSString *contentOffsetKey = @"contentOffset";

@implementation UIScrollView (DZNSegmentedControl)

#pragma mark - Getters

- (DZNSegmentedControl *)segmentedControl
{
    return objc_getAssociatedObject(self, &segmentedControlKey);
}

- (DZNScrollDirection)scrollDirection
{
    return [objc_getAssociatedObject(self, &scrollDirectionKey) integerValue];
}

- (BOOL)scrollOnSegmentChange
{
    return [objc_getAssociatedObject(self, &scrollOnSegmentChangeKey) boolValue];
}


#pragma mark - Setters

- (void)setSegmentedControl:(DZNSegmentedControl *)segmentedControl
{
    if (segmentedControl) {
        [self addObserver:self forKeyPath:contentOffsetKey options:NSKeyValueObservingOptionNew context:&observerContext];
        [segmentedControl addTarget:self action:@selector(dzn_didChangeSegement:) forControlEvents:UIControlEventValueChanged];
    }
    else if (self.segmentedControl) {
        [self removeObserver:self forKeyPath:contentOffsetKey context:&observerContext];
        [segmentedControl removeTarget:self action:@selector(dzn_didChangeSegement:) forControlEvents:UIControlEventValueChanged];
    }
    
    objc_setAssociatedObject(self, &segmentedControlKey, segmentedControl, OBJC_ASSOCIATION_ASSIGN);
    
    self.scrollOnSegmentChange = YES;
}

- (void)setScrollDirection:(DZNScrollDirection)scrollDirection
{
    objc_setAssociatedObject(self, &scrollDirectionKey, @(scrollDirection), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

- (void)setScrollOnSegmentChange:(BOOL)scrollOnSegmentChange
{
    objc_setAssociatedObject(self, &scrollOnSegmentChangeKey, @(scrollOnSegmentChange), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}


#pragma mark - Events

- (void)dzn_didChangeSegement:(id)sender
{
    if (!self.scrollOnSegmentChange) {
        return;
    }
    
    NSInteger index = self.segmentedControl.selectedSegmentIndex;
    
    CGPoint offset = CGPointZero;
    
    if (self.scrollDirection == DZNScrollDirectionHorizontal) {
        CGFloat pageWidth = CGRectGetWidth([UIScreen mainScreen].bounds);
        offset.x = pageWidth*index;
    }
    else {
        CGFloat pageHeight = CGRectGetHeight([UIScreen mainScreen].bounds);
        offset.y = pageHeight*index;
    }
    
    [self setContentOffset:offset animated:YES];
}


#pragma mark - KVO

- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary *)change context:(void *)context
{
    if ([keyPath isEqualToString:contentOffsetKey] && context == &observerContext && self.pagingEnabled)
    {
        CGPoint contentOffset = [change[NSKeyValueChangeNewKey] CGPointValue];
        
        if (self.isDragging || self.isDecelerating) {
            [self.segmentedControl setScrollOffset:contentOffset contentSize:self.contentSize];
        }
    }
}

@end
