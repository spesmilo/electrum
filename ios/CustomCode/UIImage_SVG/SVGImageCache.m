//
//  SVGImageCache.m
//  UIImage-SVG
//
//  Created by Freddie Tilley en Thijs Scheepers on 25/04/14.
//  Copyright (c) 2014 Label305 B.V. All rights reserved.
//

#import "SVGImageCache.h"

@implementation SVGImageCache

+ (instancetype)sharedImageCache
{
    static dispatch_once_t pred;
    static SVGImageCache *sharedImageCache = nil;

    dispatch_once(&pred, ^{
		sharedImageCache = [[SVGImageCache alloc] init];
    });

    return sharedImageCache;
}

- (id)init
{
	self = [super init];

	if (self) {
		self.cachedImages = [[NSMutableDictionary alloc] init];
        self.limit = 0;
	}

	return self;
}

- (void)clearImageCache:(NSDictionary *)key
{
	[self.cachedImages removeObjectForKey:key];
}

- (UIImage *)cachedImageWithKey:(NSDictionary *)key
{
	return [self.cachedImages objectForKey:key];
}

- (void)addImageToCache:(UIImage *)image forKey:(NSDictionary *)key
{
    while (self.limit > 0 && ! [self.cachedImages objectForKey:key] && self.cachedImages.count >= self.limit) {
        NSArray *keys = self.cachedImages.allKeys;
        [self.cachedImages removeObjectForKey:keys.lastObject];
    }
	[self.cachedImages setObject:image forKey:key];
}

@end
