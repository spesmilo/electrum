//
//  PocketSVG.h
//
//  Based on SvgToBezier.h, created by Martin Haywood on 5/9/11.
//  Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0) license 2011 Ponderwell.
//
//  Cleaned up by Bob Monaghan - Glue Tools LLC 6 November 2011
//  Integrated into PocketSVG 10 August 2012
//
//  MIT License

#ifdef TARGET_OS_IPHONE
#import <UIKit/UIKit.h>
typedef UIBezierPath BEZIER_PATH_TYPE;
#else
#import <Cocoa/Cocoa.h>
typedef NSBezierPath BEZIER_PATH_TYPE;
#endif

#import "RaptureXML/RXMLElement.h"

@interface PocketSVG : NSObject

@property (nonatomic, readonly) CGFloat width;
@property (nonatomic, readonly) CGFloat height;
@property (nonatomic, readonly) NSArray *beziers;

- (id) initFromSVGFile: (NSString *) filename;
- (id) initFromSVGFilename: (NSString *) filename fileExtension: (NSString *) fileExtension;
- (id) initFromSVGXML: (RXMLElement *) rootXML;
- (id) initFromSVGData: (NSData *) data;
- (id) initFromSVGString: (NSString *) svgString;

@end
