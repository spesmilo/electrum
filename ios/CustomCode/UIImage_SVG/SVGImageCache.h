//
//  SVGImageCache.h
//  UIImage-SVG
//
//  Created by Freddie Tilley en Thijs Scheepers on 25/04/14.
//  Copyright (c) 2014 Label305 B.V. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface SVGImageCache : NSObject

@property (nonatomic, readwrite) NSMutableDictionary *cachedImages;
@property (nonatomic, readwrite) NSUInteger limit; /* limit cache to this many images.. if 0, no limit */

+ (instancetype)sharedImageCache;

- (void)clearImageCache:(NSDictionary *)key;

- (UIImage *)cachedImageWithKey:(NSDictionary *)key;

- (void)addImageToCache:(UIImage *)anImage forKey:(NSDictionary *)key;

@end
