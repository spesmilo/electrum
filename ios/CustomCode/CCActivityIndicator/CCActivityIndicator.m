//
//  CCActivityIndicator.m
//
//  Created by Calin Culianu on 5/21/2018.
//  Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>. MIT License.
//

#import <CoreGraphics/CoreGraphics.h>
#import "CCActivityIndicator.h"

static const CGFloat epsilon = 0.00001;
#define DEGREES_TO_RADIANS(x) (M_PI * (x) / 180.0)
#define kNumCircles 3

@interface MyDrawer : NSObject<CALayerDelegate>
@property (nonatomic, assign) NSInteger index;
@property (nonatomic, weak) CCActivityIndicator *parent;
- (void) drawLayer:(CALayer *)layer inContext:(CGContextRef)context;
@end

@implementation CCActivityIndicator {
    MyDrawer *_drawers[kNumCircles + 1];
    CALayer *_layers[kNumCircles + 1];
}

- (void) dealloc {
    if (self.animating) self.animating = NO;
}

- (void)ccCommonInit {
    self.backgroundColor = UIColor.clearColor;
    self.opaque = NO;
    // below attempts to politely not overwrite any values set by Interface Builder
    if (!_color) self.color = UIColor.whiteColor;
    self.clearsContextBeforeDrawing = YES;
    for (int i = 0; i < kNumCircles+1; ++i) {
        CALayer *l = CALayer.layer;
        MyDrawer *d = [MyDrawer new];
        _layers[i] = l;
        _drawers[i] = d;
        d.index = i;
        d.parent = self;
        l.drawsAsynchronously = YES;
        l.needsDisplayOnBoundsChange = YES;
        l.delegate = _drawers[i];
        [self.layer addSublayer:l];
        [l setNeedsDisplay];
    }
    self.layer.needsDisplayOnBoundsChange = YES;
    [self.layer setNeedsDisplay];
}
- (instancetype)init { if ((self=[super init])) [self ccCommonInit]; return self;}
- (instancetype)initWithFrame:(CGRect)frame { if ((self=[super initWithFrame:frame])) [self ccCommonInit]; return self;}
- (instancetype)initWithCoder:(NSCoder *)coder { if ((self=[super initWithCoder:coder])) [self ccCommonInit]; return self; }

- (void)layoutSubviews {
    CGRect f = self.bounds;
    //self.layer.frame = self.frame;
    for (int i = 0; i < kNumCircles+1; ++i) {
        _layers[i].frame = f;
//        [_layers[i] setNeedsDisplay];
    }
//    [self.layer setNeedsDisplay];
}

- (void) animateLayer:(int)index {
    if (index <= 0 || index > kNumCircles) return;
    CALayer *l = _layers[index];
    // variant 1:
    //static const CGFloat kAlphaMuls[kNumCircles+1] = {0.0,0.33, 1.33, 2.12};
    // variant 2:
    //static const CGFloat kAlphaMuls[kNumCircles+1] = {0, 0.6175, 1.53, -0.98};
    // variant 3 (Max's):
    static const CGFloat kAlphaMuls[kNumCircles+1] = {0.0, 0.7, 1.2, 1.8}; //1.33, 2.12};
    CABasicAnimation* rotationAnimation;
    CGFloat gamma = kAlphaMuls[index];
    CGFloat duration = 1.0;
    rotationAnimation = [CABasicAnimation animationWithKeyPath:@"transform.rotation.z"];
    rotationAnimation.toValue = [NSNumber numberWithFloat: M_PI * 2.0 /* full rotation*/ * 1.0 * gamma ];
    rotationAnimation.duration = duration;
    rotationAnimation.cumulative = YES;
    rotationAnimation.repeatCount = HUGE_VALF;
    [l addAnimation:rotationAnimation forKey:@"rotationAnimation"];
}

- (void) setLineWidth:(CGFloat)lineWidth {
    _lineWidth = lineWidth;
    [self layoutSubviews]; // force redraw
}

- (void) setColor:(UIColor *)color {
    _color = [color copy];
    [self layoutSubviews];
}

- (BOOL) animating {
    return _layers[1].animationKeys.count;
}

- (void) setAnimating:(BOOL)b {
    if (!!self.animating == !!b) return;
    if (!b) {
        [self.layer removeAllAnimations];
        for (int i = 1; i < kNumCircles+1; ++i)
            [_layers[i] removeAllAnimations];
    } else {
        for (int i = 1; i < kNumCircles+1; ++i)
            [self animateLayer:i];
    }
}
@end
@implementation MyDrawer
- (void) drawLayer:(CALayer *)layer inContext:(CGContextRef)context {
    int index = (int)self.index;
    if (index < 0 || index > kNumCircles || !_parent) return;
    CGRect rect = CGContextGetClipBoundingBox(context);

    const CGFloat height = MIN(CGRectGetHeight(rect), CGRectGetWidth(rect));
    CGFloat lineWidth = _parent.lineWidth;
    CGFloat smallCircleHeight = height / 6.0f; //4.0f;
    if (smallCircleHeight < 4.0)
        smallCircleHeight = 4.0;

    if (lineWidth < epsilon) {
        // do auto line width based on size
        lineWidth = smallCircleHeight * 0.166;
        if (lineWidth < .5) lineWidth = .5;
    }


    const CGRect bigCircleRect = CGRectInset(rect, smallCircleHeight / 2.0f, smallCircleHeight / 2.0f);
    const CGFloat bigCircleRadius = MIN(CGRectGetHeight(bigCircleRect) / 2.0f, CGRectGetWidth(bigCircleRect) / 2.0f);

    const CGPoint rectCenter = CGPointMake(CGRectGetMidX(rect), CGRectGetMidY(rect));

    CGContextSetLineWidth(context, lineWidth);

    if (index == 0) { // big circle layer
        CGContextSetStrokeColorWithColor(context, _parent.color.CGColor);
        CGContextAddEllipseInRect(context, bigCircleRect);
        CGContextStrokePath(context);

        return;
    }

    CGContextSetFillColorWithColor(context, _parent.color.CGColor);
    static const CGFloat kSizeMuls[kNumCircles] = {1.0, 0.8, 0.6};//0.75, 0.66};
    CGFloat alpha = (index-1) * (M_PI / (kNumCircles / 2.0f));

    const CGFloat myheight = smallCircleHeight*kSizeMuls[index-1];
    CGPoint smallCircleCenter = CGPointMake(rectCenter.x  + bigCircleRadius * cos(alpha) - myheight/2.0f , rectCenter.y + bigCircleRadius * sin(alpha) - myheight / 2.0f );
    CGRect smallCircleRect = CGRectMake(smallCircleCenter.x,smallCircleCenter.y,myheight,myheight);

    CGContextAddEllipseInRect(context, smallCircleRect);
    CGContextFillPath(context);
}
@end


