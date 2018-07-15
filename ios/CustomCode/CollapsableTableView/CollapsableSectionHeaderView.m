//
//  CollapsableSectionHeaderView.m
//
//  Created by calin on 3/25/18.
//  Copyright © 2018 Calin Culianu. MIT License.
//


#import "CollapsableSectionHeaderView.h"

#define DEGREES_TO_RADIANS(x) (M_PI * (x) / 180.0)

@interface CollapsableSectionHeaderView ()
@property (weak, nonatomic) IBOutlet UIImageView *imageView;
@end

@implementation CollapsableSectionHeaderView {
    BOOL isRotating;
}

-(void)openAnimated:(BOOL)animated {
    
    if (animated && !isRotating) {
        
        isRotating = YES;
        
        [UIView animateWithDuration:0.2 delay:0.0 options: UIViewAnimationOptionAllowUserInteraction |UIViewAnimationOptionCurveLinear animations:^{
            self.imageView.transform = CGAffineTransformIdentity;
        } completion:^(BOOL finished) {
            self->isRotating = NO;
        }];
        
    } else {
        [self.layer removeAllAnimations];
        self.imageView.transform = CGAffineTransformIdentity;
        isRotating = NO;
    }
}

-(void)closeAnimated:(BOOL)animated {
    
    if (animated && !isRotating) {
        
        isRotating = YES;
        
        [UIView animateWithDuration:0.2 delay:0.0 options: UIViewAnimationOptionAllowUserInteraction |UIViewAnimationOptionCurveLinear animations:^{
            self.imageView.transform = CGAffineTransformMakeRotation(DEGREES_TO_RADIANS(-179.99f));
        } completion:^(BOOL finished) {
            self->isRotating = NO;
        }];
        
    } else {
        [self.layer removeAllAnimations];
        self.imageView.transform = CGAffineTransformMakeRotation(DEGREES_TO_RADIANS(-179.99f));
        isRotating = NO;
    }
}

@end
