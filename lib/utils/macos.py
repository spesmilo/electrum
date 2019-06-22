#!/usr/bin/env python3
#
# macos.py -  utility functions, mainly functions that call into CoreFoundation
# and Foundation
#
# Copyright © 2018 Alexander Schlarb
# Copyright © 2019 Calin Culianu <calin.culianu@gmail.com>
#
# License: MIT

import sys

if sys.platform != 'darwin':
    raise ImportError("This file can only be used on macOS")

from ctypes import (cdll, c_bool, c_char, c_ubyte, c_uint, c_void_p, c_char_p,
                    c_ssize_t, POINTER, util, cast, create_string_buffer, sizeof,
                    Structure, byref)

# macOS framework libraries used
cf_path = util.find_library('CoreFoundation')
foundation_path = util.find_library('Foundation')
if not cf_path or not foundation_path:
    raise ImportError("This module requires the macOS Foundation libraries")

cf = cdll.LoadLibrary(cf_path)
foundation = cdll.LoadLibrary(foundation_path)

# macOS Framework constants used
NSApplicationSupportDirectory = 14
NSCachesDirectory = 13
NSUserDomainMask = 1
kCFStringEncodingUTF8 = 0x08000100

# Used for type annotation
class _Void: pass

# macOS CoreFoundation types used
CFIndex = c_ssize_t
CFIndex_p = POINTER(CFIndex)

class CFArray(Structure):
    _fields_ = []
CFArray_p = POINTER(CFArray)

class CFBundle(Structure):
    _fields_ = []
CFBundle_p = POINTER(CFBundle)

class CFString(Structure):
    _fields_ = []
CFString_p = POINTER(CFString)

class CFRange(Structure):
    _fields_ = [('location', CFIndex), ('length', CFIndex)]


# Boolean CFStringGetCString(CFStringRef theString, char *buffer, CFIndex bufferSize, CFStringEncoding encoding);
cf.CFStringGetCString.restype = c_bool
cf.CFStringGetCString.argtypes = [c_void_p, c_char_p, c_ssize_t, c_uint]

# CFIndex CFStringGetLength(CFStringRef theString);
cf.CFStringGetLength.restype = CFIndex
cf.CFStringGetLength.argtypes = [CFString_p]

# CFIndex CFStringGetBytes(CFStringRef theString, CFRange range, CFStringEncoding encoding, UInt8 lossByte, Boolean isExternalRepresentation, UInt8 *buffer, CFIndex maxBufLen, CFIndex *usedBufLen)
cf.CFStringGetBytes.restype = CFIndex
cf.CFStringGetBytes.argtypes = [CFString_p, CFRange, c_uint, c_ubyte, c_bool, c_char_p, CFIndex, CFIndex_p]

# CFIndex CFArrayGetCount(CFArrayRef theArray);
cf.CFArrayGetCount.restype = CFIndex
cf.CFArrayGetCount.argtypes = [CFArray_p]

# const void* CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx);
cf.CFArrayGetValueAtIndex.restype = c_void_p
cf.CFArrayGetValueAtIndex.argtypes = [CFArray_p, CFIndex]

# void CFRelease(void *), basically
cf.CFRelease.argtypes = [c_void_p]
cf.CFRelease.restype = None

def CFString2Str(cfstr: CFString_p) -> str:
    l = cf.CFStringGetLength(cfstr)
    r = CFRange(0, l)
    blen = CFIndex(0)
    lossbyte = c_ubyte(ord(b'?'))
    slen = cf.CFStringGetBytes(cfstr, r, kCFStringEncodingUTF8, lossbyte, False, c_char_p(0), 0, byref(blen))
    buf = create_string_buffer((blen.value+1) * sizeof(c_char))
    slen = cf.CFStringGetBytes(cfstr, r, kCFStringEncodingUTF8, lossbyte, False, buf, CFIndex(blen.value+1), byref(blen))
    if slen != l:
        raise ValueError('Cannot retrieve c-string from cfstring')
    buf = bytes(buf)
    return buf[:blen.value].decode('utf-8')

def CFArrayGetIndex(array: CFArray_p, idx: int, default=_Void) -> c_void_p:
    length = cf.CFArrayGetCount(array)
    if length > idx:
        return cf.CFArrayGetValueAtIndex(array, idx)
    elif default is not _Void:
        return default
    else:
        raise IndexError("CoreFramework array index is out range: {} <= {}".format(length, idx))


import pathlib
# NSArray<NSString*>* NSSearchPathForDirectoriesInDomains(NSSearchPathDirectory directory, NSSearchPathDomainMask domainMask, BOOL expandTilde);
foundation.NSSearchPathForDirectoriesInDomains.restype = CFArray_p
foundation.NSSearchPathForDirectoriesInDomains.argtypes = [c_uint, c_uint, c_bool]

def get_user_directory(type: str) -> pathlib.Path:
    """
    Retrieve the macOS directory path for the given type
    The `type` parameter must be one of: "application-support", "cache".
    Example results:
     - '/Users/calin/Library/Application Support' (for "application-support")
     - '/Users/calin/Library/Caches' (for "cache")
    Returns the discovered path on success, `None` otherwise.
    """
    if type == 'application-support':
        ns_type = NSApplicationSupportDirectory
    elif type == 'cache':
        ns_type = NSCachesDirectory
    else:
        raise AssertionError('Unexpected directory type name')
    array = foundation.NSSearchPathForDirectoriesInDomains(ns_type, NSUserDomainMask, c_bool(True))
    result = CFArrayGetIndex(array, 0, None)
    if result is not None:
        return pathlib.Path(CFString2Str(cast(result, CFString_p)))


# CFBundleRef CFBundleGetMainBundle(void);
cf.CFBundleGetMainBundle.restype = CFBundle_p
cf.CFBundleGetMainBundle.argtypes = []

# CFStringRef CFBundleGetIdentifier(CFBundleRef bundle);
cf.CFBundleGetIdentifier.restype = CFString_p
cf.CFBundleGetIdentifier.argtypes = [CFBundle_p]

def get_bundle_identifier() -> str:
    """
    Retrieve this app's bundle identifier
    Example result: 'org.python.python'
    Returns the bundle identifier on success, `None` otherwise.
    """
    bundle = cf.CFBundleGetMainBundle()
    if bundle:
        return CFString2Str(cf.CFBundleGetIdentifier(bundle))


# CFArray CFLocaleCopyPreferredLanguages(void) // returns a copy of the current preferred languages for this user
cf.CFLocaleCopyPreferredLanguages.restype = CFArray_p
cf.CFLocaleCopyPreferredLanguages.argtypes = []

def get_preferred_languages():
    ''' Returns a list of preferred languages queried from the system using
    reliable macos calls.  This is because locale.getdefaultlocale() is
    unreliable.  The returned list is of the form:

    [
        'en_US', 'ro_US', 'el_US', 'ru_US'
    ]

    And always contains at least 1 item.
    '''
    array = cf.CFLocaleCopyPreferredLanguages()
    ret = []
    if array:
        try:
            for idx in range( cf.CFArrayGetCount(array) ):
                ret.append(CFString2Str(cast(cf.CFArrayGetValueAtIndex(array, idx), CFString_p)).replace('-', '_'))
        finally:
            # unconditional release (free) resources
            cf.CFRelease(array)
    return ret
