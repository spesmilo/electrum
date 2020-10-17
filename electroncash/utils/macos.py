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
    raise ImportError("This file can only be used on macOS or iOS")

from ctypes import (cdll, c_bool, c_char, c_ubyte, c_uint, c_void_p, c_char_p,
                    c_ssize_t, POINTER, util, cast, create_string_buffer, sizeof,
                    Structure, byref)
from enum import IntEnum

# macOS framework libraries used
cf_path = util.find_library('CoreFoundation')
foundation_path = util.find_library('Foundation')
objc_path = util.find_library('objc')
if not all((cf_path, foundation_path, objc_path)):
    raise ImportError("This module requires the CoreFoundation, Foundation and objc libraries")

cf = cdll.LoadLibrary(cf_path)
foundation = cdll.LoadLibrary(foundation_path)
objc = cdll.LoadLibrary(objc_path)

if not all((cf, foundation, objc)):
    raise ImportError("Could not load a required library")

# macOS Framework constants used
kCFStringEncodingUTF8 = 0x08000100  # utf8 string encoding
NSUserDomainMask = 1

class NSSearchPathDirectory(IntEnum):
    ''' Constants for retrieving paths using API function
    NSSearchPathForDirectoriesInDomains. From NSPathUtilities.h '''
    NSApplicationDirectory = 1  # supported applications (Applications)
    NSDemoApplicationDirectory = 2  # unsupported applications, demonstration versions (Demos)
    NSDeveloperApplicationDirectory = 3  # developer applications (Developer/Applications). DEPRECATED - there is no one single Developer directory.
    NSAdminApplicationDirectory = 4  # system and network administration applications (Administration)
    NSLibraryDirectory = 5  # various documentation, support, and configuration files, resources (Library)
    NSDeveloperDirectory = 6  # developer resources (Developer) DEPRECATED - there is no one single Developer directory.
    NSUserDirectory = 7  # user home directories (Users)
    NSDocumentationDirectory = 8  # documentation (Documentation)
    NSDocumentDirectory = 9  # documents (Documents)
    NSCoreServiceDirectory = 10  # location of CoreServices directory (System/Library/CoreServices)
    NSAutosavedInformationDirectory = 11  # location of autosaved documents (Documents/Autosaved)
    NSDesktopDirectory = 12  # location of user's desktop
    NSCachesDirectory = 13  # location of discardable cache files (Library/Caches)
    NSApplicationSupportDirectory = 14  # location of application support files (plug-ins, etc) (Library/Application Support)
    NSDownloadsDirectory = 15  # location of the user's "Downloads" directory
    NSInputMethodsDirectory = 16 # input methods (Library/Input Methods)
    NSMoviesDirectory = 17  # location of user's Movies directory (~/Movies)
    NSMusicDirectory = 18  # location of user's Music directory (~/Music)
    NSPicturesDirectory = 19  # location of user's Pictures directory (~/Pictures)
    NSPrinterDescriptionDirectory = 20  # location of system's PPDs directory (Library/Printers/PPDs)
    NSSharedPublicDirectory = 21  # location of user's Public sharing directory (~/Public)
    NSPreferencePanesDirectory = 22  # location of the PreferencePanes directory for use with System Preferences (Library/PreferencePanes)
    NSApplicationScriptsDirectory = 23  # location of the user scripts folder for the calling application (~/Library/Application Scripts/code-signing-id)
    NSItemReplacementDirectory = 99  # For use with NSFileManager's URLForDirectory:inDomain:appropriateForURL:create:error:
    NSAllApplicationsDirectory = 100  # all directories where applications can occur
    NSAllLibrariesDirectory = 101  # all directories where resources can occur
    NSTrashDirectory = 102  # location of Trash directory

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

# CFTypeRef CFRetain(CFTypeRef)
cf.CFRetain.argtypes = [c_void_p]
cf.CFRetain.restype = c_void_p

objc.objc_autoreleasePoolPush.argtypes = []
objc.objc_autoreleasePoolPush.restype = c_void_p

objc.objc_autoreleasePoolPop.argtypes = [c_void_p]
objc.objc_autoreleasePoolPop.restype = None

def CFString2Str(cfstr: CFString_p) -> str:
    l = cf.CFStringGetLength(cfstr)
    if l <= 0:
        return ''  # short circuit out if empty string or other nonsense length
    r = CFRange(0, l)
    blen = CFIndex(0)
    lossbyte = c_ubyte(ord(b'?'))
    cf.CFStringGetBytes(cfstr, r, kCFStringEncodingUTF8, lossbyte, False, c_char_p(0), 0, byref(blen))  # find out length of utf8 string in bytes, sans nul
    buf = create_string_buffer((blen.value+1) * sizeof(c_char))  # allocate buffer + nul
    num_conv = cf.CFStringGetBytes(cfstr, r, kCFStringEncodingUTF8, lossbyte, False, buf, CFIndex(blen.value+1), byref(blen))
    if not num_conv:
        raise ValueError('Unable to convert CFString to UTF8 C string')
    return bytes(buf)[:blen.value].decode('utf-8')

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

def get_user_directory(ns_type: int) -> pathlib.Path:
    """
    Retrieve the macOS directory path for the given type
    The `ns_type` parameter must be an NSSearchPathDirectory enum member.

    Example results:
     - '/Users/calin/Library/Application Support' (for NSSearchPathDirectory.NSApplicationSupportDirectory)
     - '/Users/calin/Library/Caches' (for NSSearchPathDirectory.NSCachesDirectory)
    Returns the discovered path on success, `None` otherwise.
    """
    # Note NSSearchPathForDirectoriesInDomains returns an autoreleased object,
    # so we need to push an autorelease pool and then pop an autorelease pool
    # to make sure this function never leaks.  This requires that at least one
    # top-level autorelease pool exists already (which should always be the
    # case inside a Python interpreter thread).
    pool = objc.objc_autoreleasePoolPush()
    if not pool:
        raise RuntimeError('Could not push an autorelease pool')
    try:
        array = foundation.NSSearchPathForDirectoriesInDomains(ns_type, NSUserDomainMask, c_bool(True))
        if not array:
            raise ValueError('Unexpected ns_type or unable to retrieve directory from os')
        result = CFArrayGetIndex(array, 0, None)
        if result is not None:
            return pathlib.Path(CFString2Str(cast(result, CFString_p)))
    finally:
        objc.objc_autoreleasePoolPop(pool)


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
    bundle, identifier = cf.CFBundleGetMainBundle(), None
    if bundle:
        cf.CFRetain(bundle)  # get rule, retain to make sure not freed by underlying code
        try:
            identifier = cf.CFBundleGetIdentifier(bundle)
            if identifier:
                cf.CFRetain(identifier)
                return CFString2Str(identifier)
        finally:
            # Undo above retains
            if identifier:
                cf.CFRelease(identifier)
            cf.CFRelease(bundle)
    raise RuntimeError('Unable to retrieve bundle identifier from os')


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
    else:
        raise RuntimeError('Unable to retrieve preferred languages from os')
    return ret
