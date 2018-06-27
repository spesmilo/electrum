//
//  PocketSVG.m
//
//  Based on SvgToBezier.m, created by by Martin Haywood on 5/9/11.
//  Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0) license 2011 Ponderwell.
//
//  NB: Private methods here declared in a class extension, implemented in the class' main implementation block.
//
//  Cleaned up by Bob Monaghan - Glue Tools LLC 6 November 2011
//  Integrated into PocketSVG 10 August 2012
//
// MIT License

#import "PocketSVG.h"
#import "RaptureXML/RXMLElement.h"


#pragma mark - Token class interface

@interface Token : NSObject {
	@private
	unichar        _command;
	NSMutableArray *_values;
}

- (id)initWithCommand:(unichar)commandChar;
- (void)addValue:(CGFloat)value;
- (CGFloat)parameter:(NSInteger)index;
- (NSInteger)valence;
@property(nonatomic, assign) unichar command;
@end


#pragma mark - Token class implementation

@implementation Token

@synthesize command = _command;


- (id)initWithCommand:(unichar)commandChar {
	self = [self init];
    if (self) {
		_command = commandChar;
		_values = [[NSMutableArray alloc] init];
	}
	return self;
}

- (void)addValue:(CGFloat)value {
	[_values addObject:[NSNumber numberWithDouble:value]];
}

- (CGFloat)parameter:(NSInteger)index {
	return [[_values objectAtIndex:index] doubleValue];
}

- (NSInteger)valence {
	return [_values count];
}

@end


#pragma mark - PocketSVG class private interface

@interface PocketSVG ()
{
    CGPoint        _lastPoint;
    CGPoint        _lastControlPoint;
    BOOL           _validLastControlPoint;
    NSCharacterSet *_commandSet;
    NSMutableArray *_tokens;
}

- (void)reset;

- (void) parseSVG: (RXMLElement *) rootXML;

- (NSArray *) strokesFromXML: (RXMLElement *) root;
- (BEZIER_PATH_TYPE *) bezierFromPathElement: (RXMLElement *) pathElement;
- (NSMutableArray *)parsePath:(NSString *)attr;
- (BEZIER_PATH_TYPE *) generateBezierFromTokens: (NSArray *) tokens;

- (void)appendSVGMCommand:(Token *)token toBezier: (BEZIER_PATH_TYPE *) bezier;
- (void)appendSVGLCommand:(Token *)token toBezier: (BEZIER_PATH_TYPE *) bezier;
- (void)appendSVGCCommand:(Token *)token toBezier: (BEZIER_PATH_TYPE *) bezier;
- (void)appendSVGSCommand:(Token *)token toBezier: (BEZIER_PATH_TYPE *) bezier;

@end


#pragma mark - PocketSVG class implementation

NSString* const kCommandCharString = @"CcMmLlHhVvZzqQaAsS";

@implementation PocketSVG

@synthesize width  = _width;
@synthesize height = _height;
@synthesize beziers = _beziers;


#pragma mark - designated initializers

- (id) initFromSVGFile: (NSString *) filename
{
    self = [super init];
    if (self)
    {
		_commandSet = [NSCharacterSet characterSetWithCharactersInString:kCommandCharString];
        [self reset];
        
        RXMLElement *rootXML = [RXMLElement elementFromXMLFilename: filename fileExtension: @"svg"];

        [self parseSVG: rootXML];
    }
    return self;
}

- (id) initFromSVGFilename: (NSString *) filename fileExtension: (NSString *) fileExtension
{
    self = [super init];
    if (self)
    {
		_commandSet = [NSCharacterSet characterSetWithCharactersInString:kCommandCharString];
        [self reset];
        
        RXMLElement *rootXML = [RXMLElement elementFromXMLFilename: filename fileExtension: fileExtension];
        
        [self parseSVG: rootXML];
    }
    return self;
}

- (id) initFromSVGXML: (RXMLElement *) rootXML
{
    self = [super init];
    if (self)
    {
		_commandSet = [NSCharacterSet characterSetWithCharactersInString:kCommandCharString];
        [self reset];
        
        [self parseSVG: rootXML];
    }
    return self;
}

- (id) initFromSVGData: (NSData *) data
{
    self = [super init];
    if (self)
    {
		_commandSet = [NSCharacterSet characterSetWithCharactersInString:kCommandCharString];
        [self reset];
        
        RXMLElement *rootXML = [RXMLElement elementFromXMLData: data];
        
        [self parseSVG: rootXML];
    }
    return self;
}

- (id) initFromSVGString: (NSString *) svgString
{
    self = [super init];
    if (self)
    {
		_commandSet = [NSCharacterSet characterSetWithCharactersInString:kCommandCharString];
        [self reset];
        
        // we're making an assumption here about string encoding
        RXMLElement *rootXML = [RXMLElement elementFromXMLString: svgString encoding: NSUTF8StringEncoding];
        
        [self parseSVG: rootXML];
    }
    return self;
}


// get ready to parse another path
- (void) reset
{
    _lastPoint = CGPointMake(0, 0);
    _validLastControlPoint = NO;
}


#pragma mark - parsing

// parse the SVG file into a Bezier curve
- (void) parseSVG: (RXMLElement *) rootXML
{    
    if (rootXML == nil)
    {
        NSLog(@"*** PocketSVG Error: Root element nil");
        exit(EXIT_FAILURE);
    }
    if (![rootXML.tag isEqualToString: @"svg"])
    {
        NSLog(@"*** PocketSVG Error: Root element not equal to \"svg\", instead %@:", rootXML.tag);
        exit(EXIT_FAILURE);
    }

    // get the width and height
    NSString *widthString = [rootXML attribute: @"width"];
    NSString *heightString = [rootXML attribute: @"height"];
    if (widthString == nil)
    {
        NSLog(@"width empty");
        exit(EXIT_FAILURE);
    }    
    if (heightString == nil)
    {
        NSLog(@"height empty");
        exit(EXIT_FAILURE);
    }
    
    _width = [widthString floatValue];
    _height = [heightString floatValue];
    
    // find the <path> elements
    NSArray *strokeElements = [self strokesFromXML: rootXML];
    
    // build the paths
    NSMutableArray *paths = [NSMutableArray arrayWithCapacity: [strokeElements count]];
    
    for (RXMLElement *strokeElement in strokeElements)
    {
        BEZIER_PATH_TYPE *bezier;
        NSString *name = strokeElement.tag;
        if ([name isEqualToString: @"path"])
        {
            bezier = [self bezierFromPathElement: strokeElement];
        }
        else if ([name isEqualToString: @"line"])
        {
            bezier = [self bezierFromLineElement: strokeElement];
        }
        else if ([name isEqualToString: @"polyline"])
        {
            bezier = [self bezierFromPolylineElement: strokeElement];
        }
        else
        {
            NSLog(@"unexpected stroke type: %@", name);
            exit(EXIT_FAILURE);
        }
        
        [paths addObject: bezier];
    }
    
    _beziers = [paths copy];
}

// get the line drawing elements from the SVG, recursing through any <g> group elements
- (NSArray *) strokesFromXML: (RXMLElement *) root
{
    NSMutableArray *strokeElements = [NSMutableArray array];
    
    // find the <path> elements
    [root iterate: @"*" usingBlock: ^(RXMLElement *element) {
        
        NSString *name = element.tag;
        
        if ([name isEqualToString: @"g"])
        {
            // if it's a group, recurse
            NSArray *subElements = [self strokesFromXML: element];
            
            // add the group's elements to the array
            [strokeElements addObjectsFromArray: subElements];
        }
        else 
        {
            // add the element to the array if it's a line drawing element
            if ([name isEqualToString: @"path"] ||
                [name isEqualToString: @"line"] ||
                [name isEqualToString: @"polyline"])
            {
                //NSString *name = element.tag;
                //NSLog(@"element name: %@", name);
                
                [strokeElements addObject: element];
            }
        }
    }];
    
    return [strokeElements copy];
}


#pragma mark - parse <line> element and create a bezier curve

- (BEZIER_PATH_TYPE *) bezierFromLineElement: (RXMLElement *) lineElement
{
    NSString *x1String = [lineElement attribute: @"x1"];
    NSString *y1String = [lineElement attribute: @"y1"];
    NSString *x2String = [lineElement attribute: @"x2"];
    NSString *y2String = [lineElement attribute: @"y2"];
    
    CGFloat x1 = [x1String floatValue];
    CGFloat y1 = [y1String floatValue];
    CGFloat x2 = [x2String floatValue];
    CGFloat y2 = [y2String floatValue];
    
    CGPoint startPoint = CGPointMake(x1, y1);
    CGPoint endPoint   = CGPointMake(x2, y2);
    
    BEZIER_PATH_TYPE *bezier = [[BEZIER_PATH_TYPE alloc] init];
    
#ifdef TARGET_OS_IPHONE
    [bezier moveToPoint: startPoint];
    [bezier addLineToPoint: endPoint];
#else
    [bezier moveToPoint: NSPointFromCGPoint(startPoint)];
    [bezier lineToPoint: NSPointFromCGPoint(endPoint)];
#endif
    
    return bezier;
}


#pragma mark - parse <polyline> element and create a bezier curve

- (BEZIER_PATH_TYPE *) bezierFromPolylineElement: (RXMLElement *) polylineElement
{
    NSString *pointsAttribute = [polylineElement attribute: @"points"];
    
    NSArray *pairs = [pointsAttribute componentsSeparatedByCharactersInSet: [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    
    BEZIER_PATH_TYPE *bezier = [[BEZIER_PATH_TYPE alloc] init];
    
    BOOL firstPoint = YES;
    
    for (NSString *pair in pairs)
    {
        // skip empty strings - this happens when there is more than one separator in a row
        if ([pair isEqualToString: @""]) {
            continue;
        }
        
        NSArray *coordinate = [pair componentsSeparatedByString: @","];
        if ([coordinate count] != 2)
        {
            NSLog(@"expected an x and y coordinate pair");
            exit(EXIT_FAILURE);
        }
        NSString *xString = [coordinate objectAtIndex: 0];
        NSString *yString = [coordinate objectAtIndex: 1];
        CGFloat x = [xString floatValue];
        CGFloat y = [yString floatValue];
        CGPoint point = CGPointMake(x, y);
        
        if (firstPoint)
        {
#ifdef TARGET_OS_IPHONE
            [bezier moveToPoint: point];
#else
            [bezier moveToPoint: NSPointFromCGPoint(point)];
#endif
            firstPoint = NO;
        }
        else
        {    
#ifdef TARGET_OS_IPHONE
            [bezier addLineToPoint: point];
#else
            [bezier lineToPoint: NSPointFromCGPoint(point)];
#endif
        }
    }
    
    return bezier;
}


#pragma mark - parse <path> element and create a bezier curve

// create a bezier path object from a <path> element
- (BEZIER_PATH_TYPE *) bezierFromPathElement: (RXMLElement *) pathElement
{
    // get the <path> 'd' attribute
    NSString *pathString = [pathElement attribute: @"d"];
    
    // parse them into an array of Token objects
    // one Token for each path command
    NSArray *tokens = [self parsePath: pathString];
    
    // build a bezier path from the Tokens
    BEZIER_PATH_TYPE *bezier = [self generateBezierFromTokens: tokens];
    
    return bezier;
}

// parse the <path> 'd' attribute
- (NSMutableArray *)parsePath:(NSString *)attr
{
    //NSLog(@"attributes: %@", attr);
    
    // *** first, clean up the 'd' attribute ***
    // replace all non-space whitespace and commas with space
    NSError *error = NULL;
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern: @"([\t\r\n\f,])" 
                                                                           options: NSRegularExpressionCaseInsensitive | NSRegularExpressionDotMatchesLineSeparators
                                                                             error: &error];
    NSString *newAttr = [regex stringByReplacingMatchesInString: attr
                                                        options: 0
                                                          range: NSMakeRange(0, [attr length])
                                                   withTemplate: @" "];
    
    // replace all minus signs with space and minus sign
    NSRegularExpression *minusRegex = [NSRegularExpression regularExpressionWithPattern: @"(.)-" 
                                                                                options: NSRegularExpressionCaseInsensitive
                                                                                  error: &error];    
    newAttr = [minusRegex stringByReplacingMatchesInString: newAttr
                                                   options: 0
                                                     range: NSMakeRange(0, [attr length])
                                              withTemplate: @"$1 -"];
    
    // *** next, match the commands and each command's parameters ***
    // match command followed by numbers and spaces
    NSRegularExpression *stringTokenRegex = [NSRegularExpression regularExpressionWithPattern: @"([A-Za-z][0-9-. ]+)"
                                                                                      options: NSRegularExpressionCaseInsensitive 
                                                                                        error: &error];
    NSArray *matches = [stringTokenRegex matchesInString: newAttr
                                                 options: 0
                                                   range: NSMakeRange(0, [newAttr length])];
    
	if ([matches count] == 0) {
		NSLog(@"*** PocketSVG Error: No valid path commands found in the \'d\' attribute");
		exit(EXIT_FAILURE);
	}
    
    // get the matching command strings
    NSMutableArray *stringTokens = [NSMutableArray arrayWithCapacity: [matches count]];
    for (NSTextCheckingResult *match in matches) {
        NSString *result = [newAttr substringWithRange: match.range];
        [stringTokens addObject: result];
    }

	/*
    NSLog(@"tokens:");
    for (NSString *string in stringTokens)
    {
        NSLog(@"%@", string);
    }
	 */

	// turn the command strings into Tokens, checking validity of the commands as we go
	NSMutableArray *tokens = [[NSMutableArray alloc] init];
    
    for (NSString *stringToken in stringTokens)
    {
        //NSLog(@"parsing: %@", stringToken);
        
        // get the command
        unichar command = [stringToken characterAtIndex:0];
		if (![_commandSet characterIsMember:command]) {
			NSLog(@"*** PocketSVG Error: unexpected command %c", command);
            exit(EXIT_FAILURE);
		}
        
        // get the parameters
        NSString *parameterString = [stringToken substringFromIndex: 1];
        NSArray *parameters = [parameterString componentsSeparatedByString: @" "];
        
        if ([parameters count] == 0) {
            NSLog(@"*** PocketSVG Error: no parameters for command %c", command);
            exit(EXIT_FAILURE);
        }
        
        // create the Token object
        Token *token = [[Token alloc] initWithCommand:command];
        
        //NSLog(@"command: %c", command);
        
        // parse the parameters
        // should be a series of floats
        for (NSString *parameterString in parameters)
        {
            // skip if there was more than one space in a row
            if ([parameterString length] == 0) {
                continue;
            }
            
			NSScanner *floatScanner = [NSScanner scannerWithString: parameterString];
			float value;
			if (![floatScanner scanFloat:&value]) {
				NSLog(@"*** PocketSVG Error: Path string parse error: expected float (but found %@).", parameterString);
                exit(EXIT_FAILURE);
			}
            
            //NSLog(@"parameter: %f", value);
            
            // save the parameter in the Token
			[token addValue:value];
        }

		[tokens	addObject:token];
    }
    
	return [tokens copy];
}

// build a bezier path from the Tokens
- (BEZIER_PATH_TYPE *) generateBezierFromTokens: (NSArray *) tokens
{
    BEZIER_PATH_TYPE *bezier = [[BEZIER_PATH_TYPE alloc] init];
    
    // reset the path parsing variables
	[self reset];
    
    // parse the commands from each Token
	for (Token *thisToken in tokens) {
		unichar command = [thisToken command];
		switch (command) {
			case 'M':
			case 'm':
				[self appendSVGMCommand:thisToken toBezier: bezier];
				break;
			case 'L':
			case 'l':
			case 'H':
			case 'h':
			case 'V':
			case 'v':
				[self appendSVGLCommand:thisToken toBezier: bezier];
				break;
			case 'C':
			case 'c':
				[self appendSVGCCommand:thisToken toBezier: bezier];
				break;
			case 'S':
			case 's':
				[self appendSVGSCommand:thisToken toBezier: bezier];
				break;
			case 'Z':
			case 'z':
				[bezier closePath];
				break;
			default:
				NSLog(@"*** PocketSVG Error: Cannot process command : '%c'", command);
				break;
		}
	}
	return bezier;
}


#pragma mark - build bezier path from svg path commands

- (void)appendSVGMCommand:(Token *)token toBezier: (BEZIER_PATH_TYPE *) bezier
{
	_validLastControlPoint = NO;
	NSInteger index = 0;
	BOOL first = YES;
	while (index < [token valence]) {
		CGFloat x = [token parameter:index] + ([token command] == 'm' ? _lastPoint.x : 0);
		if (++index == [token valence]) {
			NSLog(@"*** PocketSVG Error: Invalid parameter count in M style token");
			return;
		}
		CGFloat y = [token parameter:index] + ([token command] == 'm' ? _lastPoint.y : 0);
		_lastPoint = CGPointMake(x, y);
		if (first) {
			[bezier moveToPoint:_lastPoint];
			first = NO;
		}
		else {
#ifdef TARGET_OS_IPHONE
			[bezier addLineToPoint:_lastPoint];
#else
			[bezier lineToPoint:NSPointFromCGPoint(_lastPoint)];
#endif
		}
		index++;
	}
}

- (void)appendSVGLCommand:(Token *)token toBezier: (BEZIER_PATH_TYPE *) bezier
{
	_validLastControlPoint = NO;
	NSInteger index = 0;
	while (index < [token valence]) {
		CGFloat x = 0;
		CGFloat y = 0;
		switch ( [token command] ) {
			case 'l':
				x = _lastPoint.x;
				y = _lastPoint.y;
			case 'L':
				x += [token parameter:index];
				if (++index == [token valence]) {
					NSLog(@"*** PocketSVG Error: Invalid parameter count in L style token");
					return;
				}
				y += [token parameter:index];
				break;
			case 'h' :
				x = _lastPoint.x;				
			case 'H' :
				x += [token parameter:index];
				y = _lastPoint.y;
				break;
			case 'v' :
				y = _lastPoint.y;
			case 'V' :
				y += [token parameter:index];
				x = _lastPoint.x;
				break;
			default:
				NSLog(@"*** PocketSVG Error: Unrecognised L style command.");
				return;
		}
		_lastPoint = CGPointMake(x, y);
#ifdef TARGET_OS_IPHONE
		[bezier addLineToPoint:_lastPoint];
#else
		[bezier lineToPoint:NSPointFromCGPoint(_lastPoint)];
#endif
		index++;
	}
}

- (void)appendSVGCCommand:(Token *)token toBezier: (BEZIER_PATH_TYPE *) bezier
{
	NSInteger index = 0;
	while ((index + 5) < [token valence]) {  // we must have 6 floats here (x1, y1, x2, y2, x, y).
		CGFloat x1 = [token parameter:index++] + ([token command] == 'c' ? _lastPoint.x : 0);
		CGFloat y1 = [token parameter:index++] + ([token command] == 'c' ? _lastPoint.y : 0);
		CGFloat x2 = [token parameter:index++] + ([token command] == 'c' ? _lastPoint.x : 0);
		CGFloat y2 = [token parameter:index++] + ([token command] == 'c' ? _lastPoint.y : 0);
		CGFloat x  = [token parameter:index++] + ([token command] == 'c' ? _lastPoint.x : 0);
		CGFloat y  = [token parameter:index++] + ([token command] == 'c' ? _lastPoint.y : 0);
		_lastPoint = CGPointMake(x, y);
#ifdef TARGET_OS_IPHONE
		[bezier addCurveToPoint:_lastPoint 
				  controlPoint1:CGPointMake(x1,y1) 
				  controlPoint2:CGPointMake(x2, y2)];
#else
		[bezier curveToPoint:NSPointFromCGPoint(_lastPoint)
			   controlPoint1:NSPointFromCGPoint(CGPointMake(x1,y1))
			   controlPoint2:NSPointFromCGPoint(CGPointMake(x2, y2)];
#endif
        _lastControlPoint = CGPointMake(x2, y2);
		_validLastControlPoint = YES;
	}
	if (index == 0) {
		NSLog(@"*** PocketSVG Error: Insufficient parameters for C command");
	}
}

- (void)appendSVGSCommand:(Token *)token toBezier: (BEZIER_PATH_TYPE *) bezier
{
	if (!_validLastControlPoint) {
		NSLog(@"*** PocketSVG Error: Invalid last control point in S command");
	}
	NSInteger index = 0;
	while ((index + 3) < [token valence]) {  // we must have 4 floats here (x2, y2, x, y).
		CGFloat x1 = _lastPoint.x + (_lastPoint.x - _lastControlPoint.x); // + ([token command] == 's' ? lastPoint.x : 0);
		CGFloat y1 = _lastPoint.y + (_lastPoint.y - _lastControlPoint.y); // + ([token command] == 's' ? lastPoint.y : 0);
		CGFloat x2 = [token parameter:index++] + ([token command] == 's' ? _lastPoint.x : 0);
		CGFloat y2 = [token parameter:index++] + ([token command] == 's' ? _lastPoint.y : 0);
		CGFloat x  = [token parameter:index++] + ([token command] == 's' ? _lastPoint.x : 0);
		CGFloat y  = [token parameter:index++] + ([token command] == 's' ? _lastPoint.y : 0);
		_lastPoint = CGPointMake(x, y);
#ifdef TARGET_OS_IPHONE
		[bezier addCurveToPoint:_lastPoint 
				  controlPoint1:CGPointMake(x1,y1)
				  controlPoint2:CGPointMake(x2, y2)];
#else
		[bezier curveToPoint:NSPointFromCGPoint(_lastPoint)
			   controlPoint1:NSPointFromCGPoint(CGPointMake(x1,y1)) 
			   controlPoint2:NSPointFromCGPoint(CGPointMake(x2, y2)];
#endif
		_lastControlPoint = CGPointMake(x2, y2);
		_validLastControlPoint = YES;
	}
	if (index == 0) {
		NSLog(@"*** PocketSVG Error: Insufficient parameters for S command");
	}
}

@end
