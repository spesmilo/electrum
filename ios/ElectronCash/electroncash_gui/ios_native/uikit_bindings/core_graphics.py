#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
from ctypes import *
from ctypes import util
from enum import Enum

from rubicon.objc import *
import typing


# /System/Library/Frameworks/ApplicationServices.framework/Frameworks/CoreGraphics.framework/Headers/CGImage.h
kCGImageAlphaNone = 0
kCGImageAlphaPremultipliedLast = 1
kCGImageAlphaPremultipliedFirst = 2
kCGImageAlphaLast = 3
kCGImageAlphaFirst = 4
kCGImageAlphaNoneSkipLast = 5
kCGImageAlphaNoneSkipFirst = 6
kCGImageAlphaOnly = 7

kCGImageAlphaPremultipliedLast = 1

kCGBitmapAlphaInfoMask = 0x1F
kCGBitmapFloatComponents = 1 << 8

kCGBitmapByteOrderMask = 0x7000
kCGBitmapByteOrderDefault = 0 << 12
kCGBitmapByteOrder16Little = 1 << 12
kCGBitmapByteOrder32Little = 2 << 12
kCGBitmapByteOrder16Big = 3 << 12
kCGBitmapByteOrder32Big = 4 << 12

# Coregraphics stuff?
# UIKit
coregraphics = cdll.LoadLibrary(util.find_library('CoreGraphics'))

coregraphics.CGRectContainsPoint.restype = c_bool
coregraphics.CGRectContainsPoint.argtypes = [CGRect, CGPoint]
coregraphics.CGRectContainsRect.restype = c_bool
coregraphics.CGRectContainsRect.argtypes = [CGRect, CGRect]

CGRectContainsPoint = coregraphics.CGRectContainsPoint

coregraphics.CGRectOffset.restype = CGRect
coregraphics.CGRectOffset.argtypes = [CGRect, c_double, c_double]
CGRectOffset = coregraphics.CGRectOffset
