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

######################################################################

# UIKit

uikit = cdll.LoadLibrary(util.find_library('UIKit'))

uikit.UIApplicationMain.restype = c_int
uikit.UIApplicationMain.argtypes = [c_int, POINTER(c_char_p), c_void_p, c_void_p]

# NSString *NSTemporaryDirectory(void)
uikit.NSTemporaryDirectory.restype = c_void_p
uikit.NSTemporaryDirectory.argtypes = []

UIApplication = ObjCClass('UIApplication')

NSArray = ObjCClass('NSArray')
NSMutableArray = ObjCClass('NSMutableArray')
NSSet = ObjCClass('NSSet')
NSMutableSet = ObjCClass('NSMutableSet')
NSMutableData = ObjCClass('NSMutableData')

# NSLayoutConstraint.h
NSLayoutConstraint = ObjCClass('NSLayoutConstraint')

NSLayoutRelationLessThanOrEqual = -1
NSLayoutRelationEqual = 0
NSLayoutRelationGreaterThanOrEqual = 1

NSLayoutAttributeLeft = 1
NSLayoutAttributeRight = 2
NSLayoutAttributeTop = 3
NSLayoutAttributeBottom = 4
NSLayoutAttributeLeading = 5
NSLayoutAttributeTrailing = 6
NSLayoutAttributeWidth = 7
NSLayoutAttributeHeight = 8
NSLayoutAttributeCenterX = 9
NSLayoutAttributeCenterY = 10
NSLayoutAttributeBaseline = 11

NSLayoutAttributeNotAnAttribute = 0

NSLayoutFormatAlignAllLeft = (1 << NSLayoutAttributeLeft)
NSLayoutFormatAlignAllRight = (1 << NSLayoutAttributeRight)
NSLayoutFormatAlignAllTop = (1 << NSLayoutAttributeTop)
NSLayoutFormatAlignAllBottom = (1 << NSLayoutAttributeBottom)
NSLayoutFormatAlignAllLeading = (1 << NSLayoutAttributeLeading)
NSLayoutFormatAlignAllTrailing = (1 << NSLayoutAttributeTrailing)
NSLayoutFormatAlignAllCenterX = (1 << NSLayoutAttributeCenterX)
NSLayoutFormatAlignAllCenterY = (1 << NSLayoutAttributeCenterY)
NSLayoutFormatAlignAllBaseline = (1 << NSLayoutAttributeBaseline)

NSLayoutFormatAlignmentMask = 0xFFFF

NSLayoutFormatDirectionLeadingToTrailing = 0 << 16
NSLayoutFormatDirectionLeftToRight = 1 << 16
NSLayoutFormatDirectionRightToLeft = 2 << 16

NSLayoutFormatDirectionMask = 0x3 << 16

NSLayoutConstraintOrientationHorizontal = 0,
NSLayoutConstraintOrientationVertical = 1

class NSEdgetInsets(Structure):
    _fields_ = [
        ("top", CGFloat),
        ("left", CGFloat),
        ("bottom", CGFloat),
        ("right", CGFloat),
    ]

def NSEdgeInsetsMake(top, left, bottom, right):
    return NSEdgeInsets(top, left, bottom, right)


class NSLayoutPriority(Enum):
    Required = 1000
    DefaultHigh = 750
    DragThatCanResizeWindow = 510
    WindowSizeStayPut = 500
    DragThatCannotResizeWindow = 490
    DefaultLow = 250
    FittingSizeCompression = 50

# NSText.h
NSLeftTextAlignment = 0
NSRightTextAlignment = 2
NSCenterTextAlignment = 1
NSJustifiedTextAlignment = 3
NSNaturalTextAlignment = 4

NSTextAlignmentLeft = NSLeftTextAlignment
NSTextAlignmentRight = NSRightTextAlignment
NSTextAlignmentCenter = NSCenterTextAlignment
NSTextAlignmentJustified = NSJustifiedTextAlignment
NSTextAlignmentNatural = NSNaturalTextAlignment

# UIControl.h

# UIControlEvents
UIControlEventTouchDown = 1 << 0
UIControlEventTouchDownRepeat = 1 << 1
UIControlEventTouchDragInside = 1 << 2
UIControlEventTouchDragOutside = 1 << 3
UIControlEventTouchDragEnter = 1 << 4
UIControlEventTouchDragExit = 1 << 5
UIControlEventTouchUpInside = 1 << 6
UIControlEventTouchUpOutside = 1 << 7
UIControlEventTouchCancel = 1 << 8

UIControlEventValueChanged = 1 << 12
UIControlEventPrimaryActionTriggered = 1 << 13 # for buttons, etc
UIControlEventEditingDidBegin = 1 << 16
UIControlEventEditingChanged = 1 << 17
UIControlEventEditingDidEnd = 1 << 18
UIControlEventEditingDidEndOnExit = 1 << 19

UIControlEventAllTouchEvents = 0x00000FFF
UIControlEventAllEditingEvents = 0x000F0000
UIControlEventApplicationReserved = 0x0F000000
UIControlEventSystemReserved = 0xF0000000
UIControlEventAllEvents = 0xFFFFFFFF

#  UIControlContentVerticalAlignment
UIControlContentVerticalAlignmentCenter = 0
UIControlContentVerticalAlignmentTop = 1
UIControlContentVerticalAlignmentBottom = 2
UIControlContentVerticalAlignmentFill = 3

# UIControlContentHorizontalAlignment
UIControlContentHorizontalAlignmentCenter = 0
UIControlContentHorizontalAlignmentLeft = 1
UIControlContentHorizontalAlignmentRight = 2
UIControlContentHorizontalAlignmentFill = 3

# UIControlState
UIControlStateNormal = 0
UIControlStateHighlighted = 1 << 0
UIControlStateDisabled = 1 << 1
UIControlStateSelected = 1 << 2
UIControlState_ALL_RELEVANT_TUPLE = (UIControlStateNormal, UIControlStateHighlighted, UIControlStateDisabled, UIControlStateSelected)
UIControlStateApplication = 0x00FF0000
UIControlStateReserved = 0xFF000000

# UIImage.h
UIImage = ObjCClass('UIImage')

# UIImageRenderingMode
UIImageRenderingModeAutomatic = 0          # Use the default rendering mode for the context where the image is used
UIImageRenderingModeAlwaysOriginal = 1     # Always draw the original image, without treating it as a template
UIImageRenderingModeAlwaysTemplate = 2     # Always draw the image as a template image, ignoring its color information

# UIImageResizingMode enum
UIImageResizingModeTile = 0
UIImageResizingModeStretch = 1


# UIImageView.h
UIImageView = ObjCClass('UIImageView')

# UIResponder.h
UIResponder = ObjCClass('UIResponder')

# UIWindow.h
UIWindow = ObjCClass('UIWindow')

# UIWindow.h
UIWindow = ObjCClass('UIWindow')

# UIScreen.h
UIScreen = ObjCClass('UIScreen')
UIScreen.declare_class_property('mainScreen')

# UIColor.h
UIColor = ObjCClass('UIColor')

# System colors
UIColor.declare_class_property('darkTextColor')
UIColor.declare_class_property('lightTextColor')
UIColor.declare_class_property('groupTableViewBackgroundColor')

# Predefined colors
UIColor.declare_class_property('blackColor')
UIColor.declare_class_property('blueColor')
UIColor.declare_class_property('brownColor')
UIColor.declare_class_property('clearColor')
UIColor.declare_class_property('cyanColor')
UIColor.declare_class_property('darkGrayColor')
UIColor.declare_class_property('grayColor')
UIColor.declare_class_property('greenColor')
UIColor.declare_class_property('lightGrayColor')
UIColor.declare_class_property('magentaColor')
UIColor.declare_class_property('orangeColor')
UIColor.declare_class_property('purpleColor')
UIColor.declare_class_property('redColor')
UIColor.declare_class_property('whiteColor')
UIColor.declare_class_property('yellowColor')

# UIView.h
UIView = ObjCClass('UIView')

# UIWindow.h
UIWindow = ObjCClass('UIWindow')

# UILabel.h
NSLineBreakByWordWrapping = 0
NSLineBreakByCharWrapping = 1
NSLineBreakByClipping = 2
NSLineBreakByTruncatingHead = 3
NSLineBreakByTruncatingTail = 4
NSLineBreakByTruncatingMiddle = 5

UILabel = ObjCClass('UILabel')

# UINavigationController.h
UINavigationController = ObjCClass('UINavigationController')

# UIButton.h
UIButton = ObjCClass('UIButton')

UIButtonTypeCustom = 0 #                         // no button type
UIButtonTypeSystem = 1# NS_ENUM_AVAILABLE_IOS(7_0),  // standard system button
UIButtonTypeDetailDisclosure = 2
UIButtonTypeInfoLight = 3
UIButtonTypeInfoDark = 4
UIButtonTypeContactAdd = 5
UIButtonTypeRoundedRect = UIButtonTypeSystem #   // Deprecated, use UIButtonTypeSystem instead


UINavigationItem = ObjCClass('UINavigationItem')

UIToolbar = ObjCClass('UIToolbar')

# UIBarButtonItem.h
UIBarButtonItem = ObjCClass('UIBarButtonItem')

UIBarButtonSystemItemDone = 0
UIBarButtonSystemItemCancel = 1
UIBarButtonSystemItemEdit = 2
UIBarButtonSystemItemSave = 3
UIBarButtonSystemItemAdd = 4
UIBarButtonSystemItemFlexibleSpace = 5
UIBarButtonSystemItemFixedSpace = 6
UIBarButtonSystemItemCompose = 7
UIBarButtonSystemItemReply = 8
UIBarButtonSystemItemAction = 9
UIBarButtonSystemItemOrganize = 10
UIBarButtonSystemItemBookmarks = 11
UIBarButtonSystemItemSearch = 12
UIBarButtonSystemItemRefresh = 13
UIBarButtonSystemItemStop = 14
UIBarButtonSystemItemCamera = 15
UIBarButtonSystemItemTrash = 16
UIBarButtonSystemItemPlay = 17
UIBarButtonSystemItemPause = 18
UIBarButtonSystemItemRewind = 19
UIBarButtonSystemItemFastForward = 20
UIBarButtonSystemItemUndo = 21
UIBarButtonSystemItemRedo = 22
UIBarButtonSystemItemPageCurl = 23
#UIBarButtonItemStyle
UIBarButtonItemStylePlain = 0
UIBarButtonItemStyleBordered = 1
UIBarButtonItemStyleDone = 2
#UIBarMetrics
UIBarMetricsDefault = 0
UIBarMetricsCompact = 1
UIBarMetricsDefaultPrompt = 101 #// Applicable only in bars with the prompt property, such as UINavigationBar and UISearchBar
UIBarMetricsCompactPrompt = 102
UIBarMetricsLandscapePhone = UIBarMetricsCompact # NS_ENUM_DEPRECATED_IOS(5_0, 8_0, "Use UIBarMetricsCompact instead") = UIBarMetricsCompact,
UIBarMetricsLandscapePhonePrompt = UIBarMetricsCompactPrompt #NS_ENUM_DEPRECATED_IOS(7_0, 8_0, "Use UIBarMetricsCompactPrompt") = UIBarMetricsCompactPrompt,

#UIBarStyle
UIBarStyleDefault = 0
UIBarStyleBlack = 1
UIBarStyleBlackOpaque = 2
UIBarStyleBlackTranslucent = 3

# UIViewController.h
UIViewController = ObjCClass('UIViewController')

# UITabBarController.h
UITabBarController = ObjCClass('UITabBarController')

# UIRefreshControl.h
UIRefreshControl = ObjCClass('UIRefreshControl')

# UITableView.h
UITableView = ObjCClass('UITableView')
UITableViewController = ObjCClass('UITableViewController')

UITableViewStylePlain = 0
UITableViewStyleGrouped = 1

UITableViewCellAccessoryNone = 0 # don't show any accessory view
UITableViewCellAccessoryDisclosureIndicator = 1 # regular chevron. doesn't track
UITableViewCellAccessoryDetailDisclosureButton = 2 # info button w/ chevron. tracks
UITableViewCellAccessoryCheckmark = 3 # checkmark. doesn't track
UITableViewCellAccessoryDetailButton = 4 # info button. tracks

UITableViewScrollPositionNone = 0
UITableViewScrollPositionTop = 1
UITableViewScrollPositionMiddle = 2
UITableViewScrollPositionBottom = 3


NSIndexPath = ObjCClass('NSIndexPath')

UITableViewRowAnimationFade = 0
UITableViewRowAnimationRight = 1
UITableViewRowAnimationLeft = 2
UITableViewRowAnimationTop = 3
UITableViewRowAnimationBottom = 4
UITableViewRowAnimationNone = 5
UITableViewRowAnimationMiddle = 6
UITableViewRowAnimationAutomatic = 100

# UITableViewCell.h
UITableViewCell = ObjCClass('UITableViewCell')

UITableViewCellStyleDefault = 0
UITableViewCellStyleValue1 = 1
UITableViewCellStyleValue2 = 2
UITableViewCellStyleSubtitle = 3

UITableViewCellEditingStyleNone = 0
UITableViewCellEditingStyleDelete = 1
UITableViewCellEditingStyleInsert = 2

UITableViewCellSelectionStyleNone = 0
UITableViewCellSelectionStyleBlue = 1
UITableViewCellSelectionStyleGray = 2
UITableViewCellSelectionStyleDefault = 3


# UITextField.h
UITextField = ObjCClass('UITextField')

UITextBorderStyleNone = 0
UITextBorderStyleLine = 1
UITextBorderStyleBezel = 2
UITextBorderStyleRoundedRect = 3

# UITextFieldViewMode
UITextFieldViewModeNever = 0
UITextFieldViewModeWhileEditing = 1
UITextFieldViewModeUnlessEditing = 2
UITextFieldViewModeAlways = 3

UITextAutocapitalizationTypeNone = 0
UITextAutocapitalizationTypeWords = 1
UITextAutocapitalizationTypeSentences = 2
UITextAutocapitalizationTypeAllCharacters = 3

# UITextView.h
UITextView = ObjCClass('UITextView')

# UIWebView.h
UIWebView = ObjCClass('UIWebView')

# UISlider.h
UISlider = ObjCClass('UISlider')

# UISwitch.h
UISwitch = ObjCClass('UISwitch')


# Attributed String stuff
NSAttributedString = ObjCClass('NSAttributedString')
NSMutableAttributedString = ObjCClass('NSMutableAttributedString')
# Paragraph Style
NSParagraphStyle = ObjCClass('NSParagraphStyle')
NSMutableParagraphStyle = ObjCClass('NSMutableParagraphStyle')
# Below Attributes come from NSAttributedString.h
NSFontAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSFontAttributeName'))
NSParagraphStyleAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSParagraphStyleAttributeName'))
NSForegroundColorAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSForegroundColorAttributeName'))
NSBackgroundColorAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSBackgroundColorAttributeName'))
NSLigatureAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSLigatureAttributeName'))
NSKernAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSKernAttributeName'))
NSStrikethroughStyleAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSStrikethroughStyleAttributeName'))
NSUnderlineStyleAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSUnderlineStyleAttributeName'))
NSStrokeColorAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSStrokeColorAttributeName'))
NSStrokeWidthAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSStrokeWidthAttributeName'))
NSShadowAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSShadowAttributeName'))
NSTextEffectAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSTextEffectAttributeName'))
NSAttachmentAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSAttachmentAttributeName'))
NSLinkAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSLinkAttributeName'))
NSBaselineOffsetAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSBaselineOffsetAttributeName'))
NSUnderlineColorAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSUnderlineColorAttributeName'))
NSStrikethroughColorAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSStrikethroughColorAttributeName'))
NSObliquenessAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSObliquenessAttributeName'))
NSExpansionAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSExpansionAttributeName'))
NSWritingDirectionAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSWritingDirectionAttributeName'))
NSVerticalGlyphFormAttributeName = ObjCInstance(c_void_p.in_dll(uikit, 'NSVerticalGlyphFormAttributeName'))
# NSUnderlineStyle enum
NSUnderlineStyleNone        = 0x00
NSUnderlineStyleSingle      = 0x01
NSUnderlineStyleThick       = 0x02
NSUnderlineStyleDouble      = 0x09
NSUnderlinePatternSolid     = 0x0000
NSUnderlinePatternDot       = 0x0100
NSUnderlinePatternDash      = 0x0200
NSUnderlinePatternDashDot   = 0x0300
NSUnderlinePatternDashDotDot= 0x0400
NSUnderlineByWord           = 0x8000


# UIStackView.h stuff
UIStackView = ObjCClass('UIStackView')
# UIStackViewDistribution
#
#     When items do not fit (overflow) or fill (underflow) the space available
#     adjustments occur according to compressionResistance or hugging
#     priorities of items, or when that is ambiguous, according to arrangement
#     order.
UIStackViewDistributionFill = 0
#     Items are all the same size.
#     When space allows, this will be the size of the item with the largest
#     intrinsicContentSize (along the axis of the stack).
#     Overflow or underflow adjustments are distributed equally among the items.
#
#     Overflow or underflow adjustments are distributed among the items proportional
#     to their intrinsicContentSizes.
UIStackViewDistributionFillEqually = 1
#     Overflow or underflow adjustments are distributed among the items proportional to their intrinsicContentSizes.
UIStackViewDistributionFillProportionally = 2
#     Additional underflow spacing is divided equally in the spaces between the items.
#     Overflow squeezing is controlled by compressionResistance priorities followed by
#     arrangement order.
UIStackViewDistributionEqualSpacing = 3
#     Equal center-to-center spacing of the items is maintained as much
#     as possible while still maintaining a minimum edge-to-edge spacing within the
#     allowed area.
#        Additional underflow spacing is divided equally in the spacing. Overflow
#     squeezing is distributed first according to compressionResistance priorities
#     of items, then according to subview order while maintaining the configured
#     (edge-to-edge) spacing as a minimum.
UIStackViewDistributionEqualCentering = 4
# UIStackViewAlignment
#    /* Align the leading and trailing edges of vertically stacked items
#     or the top and bottom edges of horizontally stacked items tightly to the container.
#     */
UIStackViewAlignmentFill = 0
#    /* Align the leading edges of vertically stacked items
#     or the top edges of horizontally stacked items tightly to the relevant edge
#     of the container
#     */
UIStackViewAlignmentLeading = 1
UIStackViewAlignmentTop = UIStackViewAlignmentLeading
UIStackViewAlignmentFirstBaseline = 2 # Valid for horizontal axis only
#    /* Center the items in a vertical stack horizontally
#     or the items in a horizontal stack vertically
#     */
UIStackViewAlignmentCenter = 3
#    /* Align the trailing edges of vertically stacked items
#     or the bottom edges of horizontally stacked items tightly to the relevant
#     edge of the container
#     */
UIStackViewAlignmentTrailing = 4
UIStackViewAlignmentBottom = UIStackViewAlignmentTrailing
UIStackViewAlignmentLastBaseline = 5 # Valid for horizontal axis only
# For UIStackView.axis (UILayooutConstraintAxis)
UILayoutConstraintAxisHorizontal = 0
UILayoutConstraintAxisVertical = 1

# A required constraint.
UILayoutPriorityRequired = 1000
# The priority level with which a button resists compressing its content.
UILayoutPriorityDefaultHigh = 750
# The priority level at which a button hugs its contents horizontally.
UILayoutPriorityDefaultLow = 250
# The priority level with which the view wants to conform to the target size in that computation.
UILayoutPriorityFittingSizeLevel = 50

# AutoResizing Mask
UIViewAutoresizingNone                 = 0
UIViewAutoresizingFlexibleLeftMargin   = 1 << 0
UIViewAutoresizingFlexibleWidth        = 1 << 1
UIViewAutoresizingFlexibleRightMargin  = 1 << 2
UIViewAutoresizingFlexibleTopMargin    = 1 << 3
UIViewAutoresizingFlexibleHeight       = 1 << 4
UIViewAutoresizingFlexibleBottomMargin = 1 << 5

UIViewContentModeScaleToFill = 0
UIViewContentModeScaleAspectFit = 1 #      // contents scaled to fit with fixed aspect. remainder is transparent
UIViewContentModeScaleAspectFill = 2 #     // contents scaled to fill with fixed aspect. some portion of content may be clipped.
UIViewContentModeRedraw = 3 #              // redraw on bounds change (calls -setNeedsDisplay)
UIViewContentModeCenter = 4 #              // contents remain same size. positioned adjusted.
UIViewContentModeTop = 5
UIViewContentModeBottom = 6
UIViewContentModeLeft = 7
UIViewContentModeRight = 8
UIViewContentModeTopLeft = 9
UIViewContentModeTopRight = 10
UIViewContentModeBottomLeft = 11
UIViewContentModeBottomRight = 12

UIScrollView = ObjCClass('UIScrollView')

# UITextInputTraits.h
UITextAutocapitalizationTypeNone = 0
UITextAutocapitalizationTypeWords = 1
UITextAutocapitalizationTypeSentences = 2
UITextAutocapitalizationTypeAllCharacters = 3

# //
# // UITextAutocorrectionType
# //
# // Controls keyboard autocorrection behavior for a text widget.
# // Note: Some input methods do not support inline autocorrection, and
# // instead use a conversion and/or candidate selection methodology. In such
# // cases, these values are ignored by the keyboard/input method implementation.
# //
UITextAutocorrectionTypeDefault = 0
UITextAutocorrectionTypeNo = 1
UITextAutocorrectionTypeYes = 2

#//
#// UITextSpellCheckingType
#//
#// Controls the annotation of misspelled words for a text widget.
#// Note: Some input methods do not support spell checking.
UITextSpellCheckingTypeDefault = 0
UITextSpellCheckingTypeNo = 1
UITextSpellCheckingTypeYes = 2
# //
# // UIKeyboardType
# //
# // Requests that a particular keyboard type be displayed when a text widget
# // becomes first responder.
# // Note: Some keyboard/input methods types may not support every variant.
# // In such cases, the input method will make a best effort to find a close
# // match to the requested type (e.g. displaying UIKeyboardTypeNumbersAndPunctuation
# // type if UIKeyboardTypeNumberPad is not supported).
# //
UIKeyboardTypeDefault = 0 #                // Default type for the current input method.
UIKeyboardTypeASCIICapable = 1 #           // Displays a keyboard which can enter ASCII characters
UIKeyboardTypeNumbersAndPunctuation = 2 #  // Numbers and assorted punctuation.
UIKeyboardTypeURL = 3 #                    // A type optimized for URL entry (shows . / .com prominently).
UIKeyboardTypeNumberPad = 4 #              // A number pad with locale-appropriate digits (0-9, ?-?, ?-?, etc.). Suitable for PIN entry.
UIKeyboardTypePhonePad = 5 #               // A phone pad (1-9, *, 0, #, with letters under the numbers).
UIKeyboardTypeNamePhonePad = 6 #          // A type optimized for entering a person's name or phone number.
UIKeyboardTypeEmailAddress = 7 #           // A type optimized for multiple email address entry (shows space @ . prominently).
UIKeyboardTypeDecimalPad = 8 # NS_ENUM_AVAILABLE_IOS(4_1),   // A number pad with a decimal point.
UIKeyboardTypeTwitter = 9 # NS_ENUM_AVAILABLE_IOS(5_0),      // A type optimized for twitter text entry (easy access to @ #)
UIKeyboardTypeWebSearch = 10 # NS_ENUM_AVAILABLE_IOS(7_0),    // A default keyboard type with URL-oriented addition (shows space . prominently).
UIKeyboardTypeASCIICapableNumberPad = 11 # NS_ENUM_AVAILABLE_IOS(10_0), // A number pad (0-9) that will always be ASCII digits.
UIKeyboardTypeAlphabet = UIKeyboardTypeASCIICapable #, // Deprecated
# //
# // UIKeyboardAppearance
# //
# // Requests a keyboard appearance be used when a text widget
# // becomes first responder..
# // Note: Some keyboard/input methods types may not support every variant.
# // In such cases, the input method will make a best effort to find a close
# // match to the requested type.
# //
UIKeyboardAppearanceDefault = 0 #         // Default apperance for the current input method.
UIKeyboardAppearanceDark = 1 # NS_ENUM_AVAILABLE_IOS(7_0),
UIKeyboardAppearanceLight = 2 # NS_ENUM_AVAILABLE_IOS(7_0),
UIKeyboardAppearanceAlert = UIKeyboardAppearanceDark #  // Deprecated
# //
# // UIReturnKeyType
# //
# // Controls the display of the return key.
# //
# // Note: This enum is under discussion and may be replaced with a
# // different implementation.
# //
UIReturnKeyDefault = 0
UIReturnKeyGo = 1
UIReturnKeyGoogle = 2
UIReturnKeyJoin = 3
UIReturnKeyNext = 4
UIReturnKeyRoute = 5
UIReturnKeySearch = 6
UIReturnKeySend = 7
UIReturnKeyYahoo = 8
UIReturnKeyDone = 9
UIReturnKeyEmergencyCall = 10
UIReturnKeyContinue = 11

# UIAlertAction and UIAlertController stuff
UIAlertController = ObjCClass('UIAlertController')
UIAlertAction = ObjCClass('UIAlertAction')
UIAlertActionStyleDefault = 0
UIAlertActionStyleCancel = 1
UIAlertActionStyleDestructive = 2
UIAlertControllerStyleActionSheet = 0
UIAlertControllerStyleAlert = 1

# UIModalPresentationStyle
UIModalPresentationFullScreen = 0
UIModalPresentationPageSheet = 1
UIModalPresentationFormSheet = 2
UIModalPresentationCurrentContext = 3
UIModalPresentationCustom = 4
UIModalPresentationOverFullScreen = 5
UIModalPresentationOverCurrentContext = 6
UIModalPresentationPopover = 7
UIModalPresentationNone  = -1
# UIModalTransitionStyle
UIModalTransitionStyleCoverVertical = 0
UIModalTransitionStyleFlipHorizontal = 1
UIModalTransitionStyleCrossDissolve = 2
UIModalTransitionStylePartialCurl = 3

# Locale stuff
NSLocale = ObjCClass("NSLocale")

# UIPasteboard for clipboard access
UIPasteboard = ObjCClass("UIPasteboard")


# Background mode stuff
UIBackgroundFetchResultNewData = 0
UIBackgroundFetchResultNoData = 1
UIBackgroundFetchResultFailed = 2
UIBackgroundRefreshStatusRestricted = 0 #, //< unavailable on this system due to device configuration; the user cannot enable the feature
UIBackgroundRefreshStatusDenied = 1 #,     //< explicitly disabled by the user for this application
UIBackgroundRefreshStatusAvailable = 2 #   //< enabled for this application
UIApplicationStateActive = 0 #,
UIApplicationStateInactive = 1 #,
UIApplicationStateBackground = 2

UIBackgroundTaskInvalid = c_ulong.in_dll(uikit, "UIBackgroundTaskInvalid").value
UIMinimumKeepAliveTimeout = c_double.in_dll(uikit, "UIMinimumKeepAliveTimeout").value
UIApplicationBackgroundFetchIntervalMinimum = c_double.in_dll(uikit, "UIApplicationBackgroundFetchIntervalMinimum").value
UIApplicationBackgroundFetchIntervalNever = c_double.in_dll(uikit, "UIApplicationBackgroundFetchIntervalNever").value

#UITapGestureRecognizer
UIGestureRecognizer = ObjCClass('UIGestureRecognizer')
UITapGestureRecognizer = ObjCClass('UITapGestureRecognizer')

#NSNotificationCenter stuff
NSNotificationCenter = ObjCClass('NSNotificationCenter')
UIApplicationDidReceiveMemoryWarningNotification = ObjCInstance(c_void_p.in_dll(uikit, "UIApplicationDidReceiveMemoryWarningNotification"))
UIKeyboardWillShowNotification  = ObjCInstance(c_void_p.in_dll(uikit, "UIKeyboardWillShowNotification"))
UIKeyboardDidShowNotification = ObjCInstance(c_void_p.in_dll(uikit, "UIKeyboardDidShowNotification"))
UIKeyboardWillHideNotification = ObjCInstance(c_void_p.in_dll(uikit, "UIKeyboardWillHideNotification"))
UIKeyboardDidHideNotification = ObjCInstance(c_void_p.in_dll(uikit, "UIKeyboardDidHideNotification"))
UIKeyboardFrameBeginUserInfoKey = ObjCInstance(c_void_p.in_dll(uikit, "UIKeyboardFrameBeginUserInfoKey"))# NSValue of CGRect
UIKeyboardFrameEndUserInfoKey = ObjCInstance(c_void_p.in_dll(uikit, "UIKeyboardFrameEndUserInfoKey"))# NSValue of CGRect
UIKeyboardAnimationDurationUserInfoKey = ObjCInstance(c_void_p.in_dll(uikit, "UIKeyboardAnimationDurationUserInfoKey"))# NSNumber of double
UIKeyboardAnimationCurveUserInfoKey = ObjCInstance(c_void_p.in_dll(uikit, "UIKeyboardAnimationCurveUserInfoKey"))# NSNumber of NSUInteger (UIViewAnimationCurve)
UIKeyboardIsLocalUserInfoKey = ObjCInstance(c_void_p.in_dll(uikit, "UIKeyboardIsLocalUserInfoKey"))# NSNumber of BOOL

#NSFileManager
NSFileManager = ObjCClass("NSFileManager")

#UIDevice
UIDevice = ObjCClass('UIDevice')

#UIDeviceOrientation
UIDeviceOrientationUnknown = 0
UIDeviceOrientationPortrait = 1  #,            // Device oriented vertically, home button on the bottom
UIDeviceOrientationPortraitUpsideDown = 2  #,  // Device oriented vertically, home button on the top
UIDeviceOrientationLandscapeLeft = 3  #,       // Device oriented horizontally, home button on the right
UIDeviceOrientationLandscapeRight = 4  #,      // Device oriented horizontally, home button on the left
UIDeviceOrientationFaceUp = 5  #,              // Device oriented flat, face up
UIDeviceOrientationFaceDown = 5  #             // Device oriented flat, face down
UIInterfaceOrientationUnknown            = UIDeviceOrientationUnknown
UIInterfaceOrientationPortrait           = UIDeviceOrientationPortrait
UIInterfaceOrientationPortraitUpsideDown = UIDeviceOrientationPortraitUpsideDown
UIInterfaceOrientationLandscapeLeft      = UIDeviceOrientationLandscapeRight
UIInterfaceOrientationLandscapeRight     = UIDeviceOrientationLandscapeLeft
UIInterfaceOrientationMaskPortrait = (1 << UIInterfaceOrientationPortrait)
UIInterfaceOrientationMaskLandscapeLeft = (1 << UIInterfaceOrientationLandscapeLeft)
UIInterfaceOrientationMaskLandscapeRight = (1 << UIInterfaceOrientationLandscapeRight)
UIInterfaceOrientationMaskPortraitUpsideDown = (1 << UIInterfaceOrientationPortraitUpsideDown)
UIInterfaceOrientationMaskLandscape = (UIInterfaceOrientationMaskLandscapeLeft | UIInterfaceOrientationMaskLandscapeRight)
UIInterfaceOrientationMaskAll = (UIInterfaceOrientationMaskPortrait | UIInterfaceOrientationMaskLandscapeLeft | UIInterfaceOrientationMaskLandscapeRight | UIInterfaceOrientationMaskPortraitUpsideDown)
UIInterfaceOrientationMaskAllButUpsideDown = (UIInterfaceOrientationMaskPortrait | UIInterfaceOrientationMaskLandscapeLeft | UIInterfaceOrientationMaskLandscapeRight)


#UIDeviceBatteryState
UIDeviceBatteryStateUnknown = 0
UIDeviceBatteryStateUnplugged = 1  #,   // on battery, discharging
UIDeviceBatteryStateCharging = 2  #,    // plugged in, less than 100%
UIDeviceBatteryStateFull = 3  #,        // plugged in, at 100%

#UIUserInterfaceIdiom
UIUserInterfaceIdiomUnspecified = -1
UIUserInterfaceIdiomPhone = 0  # NS_ENUM_AVAILABLE_IOS(3_2), // iPhone and iPod touch style UI
UIUserInterfaceIdiomPad = 1  # NS_ENUM_AVAILABLE_IOS(3_2), // iPad style UI
UIUserInterfaceIdiomTV = 2  # NS_ENUM_AVAILABLE_IOS(9_0), // Apple TV style UI
UIUserInterfaceIdiomCarPlay = 3  # NS_ENUM_AVAILABLE_IOS(9_0), // CarPlay style UI

def UI_USER_INTERFACE_IDIOM() -> int:
    if UIDevice.currentDevice.respondsToSelector_(SEL(b'userInterfaceIdiom')):
        return UIDevice.currentDevice.userInterfaceIdiom
    return UIUserInterfaceIdiomPhone

#UIStatusBarStyle
UIStatusBarStyleDefault = 0  #, // Dark content, for use on light backgrounds
UIStatusBarStyleLightContent = 1  #, // Light content, for use on dark backgrounds
UIStatusBarStyleBlackTranslucent = 1 # DEPRECATED
UIStatusBarStyleBlackOpaque = 2 # DEPRECATED "Use UIStatusBarStyleLightContent")

#UIStatusBarAnimation
UIStatusBarAnimationNone = 0
UIStatusBarAnimationFade = 1
UIStatusBarAnimationSlide = 2

#// Note that UIInterfaceOrientationLandscapeLeft is equal to UIDeviceOrientationLandscapeRight (and vice versa).
#// This is because rotating the device to the left requires rotating the content to the right.
#UIInterfaceOrientation
UIInterfaceOrientationUnknown            = UIDeviceOrientationUnknown
UIInterfaceOrientationPortrait           = UIDeviceOrientationPortrait
UIInterfaceOrientationPortraitUpsideDown = UIDeviceOrientationPortraitUpsideDown
UIInterfaceOrientationLandscapeLeft      = UIDeviceOrientationLandscapeRight
UIInterfaceOrientationLandscapeRight     = UIDeviceOrientationLandscapeLeft

#UIInterfaceOrientationMask
UIInterfaceOrientationMaskPortrait = (1 << UIInterfaceOrientationPortrait)
UIInterfaceOrientationMaskLandscapeLeft = (1 << UIInterfaceOrientationLandscapeLeft)
UIInterfaceOrientationMaskLandscapeRight = (1 << UIInterfaceOrientationLandscapeRight)
UIInterfaceOrientationMaskPortraitUpsideDown = (1 << UIInterfaceOrientationPortraitUpsideDown)
UIInterfaceOrientationMaskLandscape = (UIInterfaceOrientationMaskLandscapeLeft | UIInterfaceOrientationMaskLandscapeRight)
UIInterfaceOrientationMaskAll = (UIInterfaceOrientationMaskPortrait | UIInterfaceOrientationMaskLandscapeLeft | UIInterfaceOrientationMaskLandscapeRight | UIInterfaceOrientationMaskPortraitUpsideDown)
UIInterfaceOrientationMaskAllButUpsideDown = (UIInterfaceOrientationMaskPortrait | UIInterfaceOrientationMaskLandscapeLeft | UIInterfaceOrientationMaskLandscapeRight)

# Font weight stuff
UIFontWeightUltraLight = c_double.in_dll(uikit, "UIFontWeightUltraLight").value
UIFontWeightThin = c_double.in_dll(uikit, "UIFontWeightThin").value
UIFontWeightLight = c_double.in_dll(uikit, "UIFontWeightLight").value
UIFontWeightRegular = c_double.in_dll(uikit, "UIFontWeightRegular").value
UIFontWeightMedium = c_double.in_dll(uikit, "UIFontWeightMedium").value
UIFontWeightSemibold = c_double.in_dll(uikit, "UIFontWeightSemibold").value
UIFontWeightBold = c_double.in_dll(uikit, "UIFontWeightBold").value
UIFontWeightHeavy = c_double.in_dll(uikit, "UIFontWeightHeavy").value
UIFontWeightBlack = c_double.in_dll(uikit, "UIFontWeightBlack").value

# NSDate
NSDate = ObjCClass('NSDate')

# UINib
UINib = ObjCClass('UINib')

NSUIntegerMax = ~0

# UIPopoverController
UIPopoverController = ObjCClass('UIPopoverController')
UIPopoverArrowDirectionUp = 1 << 0
UIPopoverArrowDirectionDown = 1 << 1
UIPopoverArrowDirectionLeft = 1 << 2
UIPopoverArrowDirectionRight = 1 << 3
UIPopoverArrowDirectionAny = UIPopoverArrowDirectionUp | UIPopoverArrowDirectionDown | UIPopoverArrowDirectionLeft | UIPopoverArrowDirectionRight,
UIPopoverArrowDirectionUnknown = NSUIntegerMax

# UIActivityViewController
UIActivityViewController = ObjCClass('UIActivityViewController')
# UIActivityType (NSString constants in UIKit dll)
UIActivityTypePostToFacebook     = ObjCInstance(c_void_p.in_dll(uikit, "UIActivityTypePostToFacebook"))
UIActivityTypePostToTwitter      = ObjCInstance(c_void_p.in_dll(uikit, "UIActivityTypePostToTwitter"))
UIActivityTypePostToWeibo        = ObjCInstance(c_void_p.in_dll(uikit, "UIActivityTypePostToWeibo"))
UIActivityTypeMessage            = ObjCInstance(c_void_p.in_dll(uikit, "UIActivityTypeMessage"))
UIActivityTypeMail               = ObjCInstance(c_void_p.in_dll(uikit, "UIActivityTypeMail"))
UIActivityTypePrint              = ObjCInstance(c_void_p.in_dll(uikit, "UIActivityTypePrint"))
UIActivityTypeCopyToPasteboard   = ObjCInstance(c_void_p.in_dll(uikit, "UIActivityTypeCopyToPasteboard"))
UIActivityTypeAssignToContact    = ObjCInstance(c_void_p.in_dll(uikit, "UIActivityTypeAssignToContact"))
UIActivityTypeSaveToCameraRoll   = ObjCInstance(c_void_p.in_dll(uikit, "UIActivityTypeSaveToCameraRoll"))
UIActivityTypeAddToReadingList   = ObjCInstance(c_void_p.in_dll(uikit, "UIActivityTypeAddToReadingList"))
UIActivityTypePostToFlickr       = ObjCInstance(c_void_p.in_dll(uikit, "UIActivityTypePostToFlickr"))
UIActivityTypePostToVimeo        = ObjCInstance(c_void_p.in_dll(uikit, "UIActivityTypePostToVimeo"))
UIActivityTypePostToTencentWeibo = ObjCInstance(c_void_p.in_dll(uikit, "UIActivityTypePostToTencentWeibo"))
UIActivityTypeAirDrop            = ObjCInstance(c_void_p.in_dll(uikit, "UIActivityTypeAirDrop"))
UIActivityTypeOpenInIBooks       = ObjCInstance(c_void_p.in_dll(uikit, "UIActivityTypeOpenInIBooks"))

# UIContextualAction stuff for TableViews -- available iOS 11.0+, which is why we wrap it in a try/except block
HAVE_UI_SWIPE_ACTION = False
try:
    UISwipeActionsConfiguration = ObjCClass('UISwipeActionsConfiguration')
    UIContextualAction = ObjCClass('UIContextualAction')
    UIContextualActionStyleNormal = 0
    UIContextualActionStyleDestructive = 1
    HAVE_UI_SWIPE_ACTION = True
except NameError as e:
    print("iOS 11.0+ UI Swipe Action facility missing, exception was:","["+str(e)+"]")

CIColor = ObjCClass('CIColor') # be careful using CIColor -- it has been known to not work due to iOS bugs

UIStoryboard = ObjCClass('UIStoryboard')
UIPageViewController = ObjCClass('UIPageViewController')
#typedef NS_ENUM(NSInteger, UIPageViewControllerNavigationOrientation) {
UIPageViewControllerNavigationOrientationHorizontal = 0
UIPageViewControllerNavigationOrientationVertical = 1
#typedef NS_ENUM(NSInteger, UIPageViewControllerSpineLocation) { // Only pertains to 'UIPageViewControllerTransitionStylePageCurl'.
UIPageViewControllerSpineLocationNone = 0 #, // Returned if 'spineLocation' is queried when 'transitionStyle' is not 'UIPageViewControllerTransitionStylePageCurl'.
UIPageViewControllerSpineLocationMin = 1  #,  // Requires one view controller.
UIPageViewControllerSpineLocationMid = 2  #,  // Requires two view controllers.
UIPageViewControllerSpineLocationMax = 3  # // Requires one view controller.
#typedef NS_ENUM(NSInteger, UIPageViewControllerNavigationDirection) { // For 'UIPageViewControllerNavigationOrientationHorizontal', 'forward' is right-to-left, like pages in a book. For 'UIPageViewControllerNavigationOrientationVertical', bottom-to-top, like pages in a wall calendar.
UIPageViewControllerNavigationDirectionForward = 0
UIPageViewControllerNavigationDirectionReverse = 1
#typedef NS_ENUM(NSInteger, UIPageViewControllerTransitionStyle) {
UIPageViewControllerTransitionStylePageCurl = 0 #, // Navigate between views via a page curl transition.
UIPageViewControllerTransitionStyleScroll = 1   #// Navigate between views by scrolling.

NSNumber = ObjCClass('NSNumber')

#UIVisualEffect stuff
UIBlurEffectStyleExtraLight = 0
UIBlurEffectStyleLight = 1
UIBlurEffectStyleDark = 2
UIBlurEffectStyleExtraDark = 3 #__TVOS_AVAILABLE(10_0) __IOS_PROHIBITED __WATCHOS_PROHIBITED,
UIBlurEffectStyleRegular = 4 #NS_ENUM_AVAILABLE_IOS(10_0), // Adapts to user interface style
UIBlurEffectStyleProminent = 5#NS_ENUM_AVAILABLE_IOS(10_0), // Adapts to user interface style

UIBlurEffect = ObjCClass('UIBlurEffect')
UIVisualEffectView = ObjCClass('UIVisualEffectView')

# Window Level  -- CGFloat, with 0.0 being default for all windows. In case we want to raise/lower window levels...
UIWindowLevelNormal          = float(c_double.in_dll(uikit, "UIWindowLevelNormal").value)
UIWindowLevelAlert           = float(c_double.in_dll(uikit, "UIWindowLevelAlert").value)
UIWindowLevelStatusBar       = float(c_double.in_dll(uikit, "UIWindowLevelStatusBar").value)
