#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
from ctypes import *
from ctypes import util


from rubicon.objc import *

######################################################################

# FOUNDATION

foundation = cdll.LoadLibrary(util.find_library('Foundation'))

foundation.NSMouseInRect.restype = c_bool
foundation.NSMouseInRect.argtypes = [NSPoint, NSRect, c_bool]


# NSArray.h

NSMutableArray = ObjCClass('NSMutableArray')

# NSData.h

NSData = ObjCClass('NSData')

# NSURL.h

NSURL = ObjCClass('NSURL')

# NSURLRequest.h

NSURLRequest = ObjCClass('NSURLRequest')

# UIFont.h

UIFont = ObjCClass('UIFont')

# NSTimer
NSTimer = ObjCClass('NSTimer')

NSThread = ObjCClass('NSThread')
NSInvocation = ObjCClass('NSInvocation')
NSMethodSignature = ObjCClass('NSMethodSignature')
NSEnumerator = ObjCClass('NSEnumerator')
NSBundle = ObjCClass('NSBundle')
#NSNumber = ObjCClass('NSNumber')

NSRunLoop = ObjCClass('NSRunLoop')
NSDefaultRunLoopMode='kCFRunLoopDefaultMode'
