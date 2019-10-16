//
//  HelpfulGlue.m
//  Electron-Cash
//
//  Created by calin on 2/23/18.
//  Copyright © 2018 Calin Culianu. MIT License
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <Python.h>
#include <dispatch/dispatch.h>

@interface HelpfulGlue : NSObject {
}
@end

typedef void(^VoidBlock)(void);

@implementation HelpfulGlue
+ (void) NSLogString:(NSString *)string {
    NSLog(@"%@",string);
}

+ (void) performBlockInMainThread:(VoidBlock)block sync:(BOOL)sync {
    if (!block) return;
    if (sync) {
        if (NSThread.currentThread.isMainThread) {
            block();
        } else {
            dispatch_sync(dispatch_get_main_queue(), block);
        }
    } else {
        dispatch_async(dispatch_get_main_queue(), block);
    }
}

+ (BOOL) isDebugBuild {
#ifdef DEBUG
    return YES;
#else
    return NO;
#endif
}

+ (BOOL) isSimulator {
#if TARGET_OS_SIMULATOR
    return YES;
#else
    return NO;
#endif
}

@end
