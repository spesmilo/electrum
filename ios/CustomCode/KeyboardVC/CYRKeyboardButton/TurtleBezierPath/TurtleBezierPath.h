//
//  TurtleBezierPath.h
//  TurtleBezierPath demo
//
//  Created by Nigel Barber on 09/12/2013.
//  Copyright (c) 2013 Nigel Barber. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface TurtleBezierPath : UIBezierPath

@property( nonatomic, assign ) CGFloat bearing;
@property( nonatomic, assign ) BOOL penUp;

-(CGRect)boundsWithStroke;
-(CGRect)boundsForView;

-(void)home;
-(void)forward:(CGFloat)distance;
-(void)turn:(CGFloat)angle;
-(void)leftArc:(CGFloat)radius turn:(CGFloat)angle;
-(void)rightArc:(CGFloat)radius turn:(CGFloat)angle;
-(void)down;
-(void)up;

-(void)centreInBounds:(CGRect)bounds;

@end
