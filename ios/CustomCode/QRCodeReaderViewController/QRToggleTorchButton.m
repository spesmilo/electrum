/*
 * QRCodeReaderViewController
 *
 * Copyright 2014-present Yannick Loriot.
 * http://yannickloriot.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#import "QRToggleTorchButton.h"

@implementation QRToggleTorchButton

- (id)initWithFrame:(CGRect)frame
{
  if ((self = [super initWithFrame:frame])) {
    _edgeColor            = [UIColor whiteColor];
    _fillColor            = [UIColor darkGrayColor];
    _edgeHighlightedColor = [UIColor whiteColor];
    _fillHighlightedColor = [UIColor blackColor];
  }
  return self;
}

- (void)drawRect:(CGRect)rect
{
  // Colors

  UIColor *paintColor  = (self.state != UIControlStateHighlighted) ? _fillColor : _fillHighlightedColor;
  UIColor *strokeColor = (self.state != UIControlStateHighlighted) ? _edgeColor : _edgeHighlightedColor;

  // Torch box

  CGFloat width   = rect.size.width;
  CGFloat height  = rect.size.height;
  CGFloat centerX = width / 2;
  CGFloat centerY = height / 2;

  CGFloat strokeLineWidth      = 2;
  CGFloat circleRadius         = width / 10;
  CGFloat lineLength           = width / 10;
  CGFloat lineOffset           = width / 10;
  CGFloat lineOriginFromCenter = circleRadius + lineOffset;

  //Circle
  UIBezierPath *circlePath = [UIBezierPath bezierPath];
  [circlePath addArcWithCenter:CGPointMake(centerX, centerY) radius:circleRadius startAngle:0.0 endAngle:M_PI clockwise:YES];
  [circlePath addArcWithCenter:CGPointMake(centerX, centerY) radius:circleRadius startAngle:M_PI endAngle:M_PI * 2 clockwise:YES];

  // Draw beams
  [paintColor setFill];
  
  for (int i = 0; i < 8; i++) {
    CGFloat angle = ((2 * M_PI) / 8) * i;

    CGPoint startPoint = CGPointMake(centerX + cos(angle) * lineOriginFromCenter, centerY + sin(angle) * lineOriginFromCenter);
    CGPoint endPoint   = CGPointMake(centerX + cos(angle) * (lineOriginFromCenter + lineLength), centerY + sin(angle) * (lineOriginFromCenter + lineLength));

    UIBezierPath *beamPath = [self linePathWithStartPoint:startPoint endPoint:endPoint thickness:strokeLineWidth];
    [beamPath stroke];
  }

  // Draw circle
  [strokeColor setFill];

  circlePath.lineWidth = strokeLineWidth;
  [circlePath fill];
  [circlePath stroke];
}

- (UIBezierPath *)linePathWithStartPoint:(CGPoint)startPoint endPoint:(CGPoint)endPoint thickness:(CGFloat)thickness {
  UIBezierPath *linePath = [UIBezierPath bezierPath];

  [linePath moveToPoint:startPoint];
  [linePath addLineToPoint:endPoint];

  linePath.lineCapStyle = kCGLineCapRound;
  linePath.lineWidth    = thickness;

  return linePath;
}

// MARK: - UIResponder Methods

- (void)touchesBegan:(NSSet *)touches withEvent:(UIEvent *)event
{
  [super touchesBegan:touches withEvent:event];

  [self setNeedsDisplay];
}

- (void)touchesMoved:(NSSet *)touches withEvent:(UIEvent *)event
{
  [super touchesMoved:touches withEvent:event];

  [self setNeedsDisplay];
}

- (void)touchesEnded:(NSSet *)touches withEvent:(UIEvent *)event
{
  [super touchesEnded:touches withEvent:event];

  [self setNeedsDisplay];
}

- (void)touchesCancelled:(NSSet *)touches withEvent:(UIEvent *)event
{
  [super touchesCancelled:touches withEvent:event];
  
  [self setNeedsDisplay];
}

@end
