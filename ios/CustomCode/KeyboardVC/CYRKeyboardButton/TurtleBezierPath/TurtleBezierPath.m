//
//  TurtleBezierPath.m
//  TurtleBezierPath demo
//
//  Created by Nigel Barber on 09/12/2013.
//  Copyright (c) 2013 Nigel Barber. All rights reserved.
//

#import "TurtleBezierPath.h"

@implementation TurtleBezierPath


#pragma mark - NSCoding

-(void)encodeWithCoder:(NSCoder *)aCoder
{
    [ super encodeWithCoder:aCoder ];
    
    [ aCoder encodeFloat:self.bearing forKey:@"bearing" ];
    [ aCoder encodeBool:self.penUp forKey:@"penUp" ];
}

- (id)initWithCoder:(NSCoder *)aDecoder
{
    if( self = [ super initWithCoder:aDecoder ])
    {
        self.bearing = [ aDecoder decodeFloatForKey:@"bearing" ];
        self.penUp = [ aDecoder decodeBoolForKey:@"penUp" ];
    }
    
    return self;
}


#pragma mark - NSCopying

-(id)copyWithZone:(NSZone *)zone
{
    TurtleBezierPath *clone = [[ TurtleBezierPath allocWithZone:zone ] init ];
    clone.CGPath = self.CGPath;
    clone.lineCapStyle = self.lineCapStyle;
    clone.lineJoinStyle = self.lineJoinStyle;
    clone.lineWidth = self.lineWidth;
    clone.miterLimit = self.miterLimit;
    clone.flatness = self.flatness;
    clone.usesEvenOddFillRule = self.usesEvenOddFillRule;
    
    CGFloat phase;
    NSInteger count;
    [ self getLineDash:nil count:&count phase:&phase ];
    CGFloat *lineDash = malloc( count * sizeof( CGFloat ));
    [ self getLineDash:lineDash count:&count phase:&phase ];
    [ clone setLineDash:lineDash count:count phase:phase ];
    free( lineDash );
    
    clone.bearing = self.bearing;
    clone.penUp = self.penUp;
    
    return clone;
}


#pragma mark - Private methods

-(void)arc:(CGFloat)radius turn:(CGFloat)angle clockwise:(BOOL)clockwise
{
    CGFloat radiusTurn = ( clockwise ) ? 90.0f : -90.0f;
    CGFloat cgAngleBias = ( clockwise ) ? 180.0f : 0.0f;
    angle = ( clockwise ) ? angle : -angle;
    
    CGPoint centre = [ self toCartesian:radius bearing:self.bearing + radiusTurn origin:self.currentPoint ];
    
    CGFloat cgStartAngle = cgAngleBias + self.bearing;
    CGFloat cgEndAngle = cgAngleBias + ( self.bearing + angle );
    
    self.bearing += angle;
    CGPoint endPoint = [ self toCartesian:radius bearing:( self.bearing -radiusTurn ) origin:centre ];
    
    if( self.penUp )
    {
        [ self moveToPoint:endPoint ];
    }
    else
    {
        [ self addArcWithCenter:centre radius:radius startAngle:radians( cgStartAngle ) endAngle:radians( cgEndAngle ) clockwise:clockwise ];
    }
}


#pragma mark - Public methods

-(CGRect)boundsWithStroke
{
    return CGRectIntegral( CGRectInset( self.bounds, -self.lineWidth * 0.5f, -self.lineWidth * 0.5f ));
}

-(CGRect)boundsForView
{
    CGRect bounds = self.boundsWithStroke;
    CGFloat maxWidth = MAX( fabs( CGRectGetMinX( bounds )), fabs( CGRectGetMaxX( bounds )));
    CGFloat maxHeight = MAX( fabs( CGRectGetMinY( bounds )), fabs( CGRectGetMaxY( bounds )));
    
    return CGRectMake( 0.0f, 0.0f, maxWidth * 2.0f, maxHeight * 2.0f );
}

-(BOOL)isEqual:(TurtleBezierPath *)aPath
{
    return [[ NSKeyedArchiver archivedDataWithRootObject:self ] isEqualToData:[ NSKeyedArchiver archivedDataWithRootObject:aPath ]];
}

-(void)home
{
    [ self moveToPoint:CGPointZero ];
    self.bearing = 0.0f;
}

-(void)forward:(CGFloat)distance
{
    CGPoint endPoint = [ self toCartesian:distance bearing:self.bearing origin:self.currentPoint ];
    
    if( self.penUp )
    {
        [ self moveToPoint:endPoint ];
    }
    else
    {
        [ self addLineToPoint:endPoint ];
    }
}

-(void)turn:(CGFloat)angle
{
    self.bearing += angle;
}

-(void)leftArc:(CGFloat)radius turn:(CGFloat)angle
{
    [ self arc:radius turn:angle clockwise:NO ];
}

-(void)rightArc:(CGFloat)radius turn:(CGFloat)angle
{
    [ self arc:radius turn:angle clockwise:YES ];
}

-(void)down
{
    self.penUp = NO;
}

-(void)up
{
    self.penUp = YES;
}

-(void)centreInBounds:(CGRect)bounds
{
    [ self applyTransform:CGAffineTransformMakeTranslation( bounds.size.width / 2.0f, bounds.size.height / 2.0f )];
}


#pragma mark - Maths

static inline CGFloat radians (CGFloat degrees) {return degrees * M_PI / 180.0;}

-(CGPoint)toCartesian:(CGFloat)radius bearing:(CGFloat)bearing origin:(CGPoint)origin
{
    CGFloat bearingInRadians = radians( bearing );
    
    CGPoint vector = CGPointMake( radius * sinf( bearingInRadians ), -radius * cosf( bearingInRadians ));
    
    return CGPointMake( origin.x + vector.x, origin.y + vector.y );
}


@end
