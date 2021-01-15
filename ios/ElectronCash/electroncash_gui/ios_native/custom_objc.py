#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
import sys

try:
    from .uikit_bindings import *
except Exception as e:
    sys.exit("Error: Could not import iOS libs: %s"%str(e))

##############################################################################
# QRCodeReader stuff
##############################################################################
# Custom class for accessing camera to read QRCodes
QRCodeReader = ObjCClass('QRCodeReader')
QRCodeReaderViewController = ObjCClass('QRCodeReaderViewController')

##############################################################################
# HelpfulGlue
##############################################################################
# My general utility class in HelpfulGlue.m
HelpfulGlue = ObjCClass('HelpfulGlue')


##############################################################################
# CWStatusBarNotification
##############################################################################
# For status bar notification stuff
CWStatusBarNotification = ObjCClass('CWStatusBarNotification')
# **
#  * @typedef CWNotificationStyle
#  * @brief Determines the notification style.
#  */
# typedef NS_ENUM(NSInteger, CWNotificationStyle) {
# /// Covers the status bar portion of the screen.
CWNotificationStyleStatusBarNotification = 0
# /// Covers the status bar and navigation bar portions of the screen.
CWNotificationStyleNavigationBarNotification = 1

# /**
#  * @typedef CWNotificationAnimationStyle
#  * @brief Determines the direction of animation for the notification.
#  */
# typedef NS_ENUM(NSInteger, CWNotificationAnimationStyle) {
# /// Animate in from the top or animate out to the top
CWNotificationAnimationStyleTop = 0
# /// Animate in from the bottom or animate out to the bottom.
CWNotificationAnimationStyleBottom = 1
# /// Animate in from the left or animate out to the left.
CWNotificationAnimationStyleLeft = 2
# /// Animate in from the right or animate out to the right.
CWNotificationAnimationStyleRight = 3
# /**
#  * @typedef CWNotificationAnimationType
#  * @brief Determines whether the notification moves the existing content out of
#  * the way or simply overlays it.
#  */
# typedef NS_ENUM(NSInteger, CWNotificationAnimationType) {
# /// Moves existing content out of the way.
CWNotificationAnimationTypeReplace = 0
# /// Overlays existing content.
CWNotificationAnimationTypeOverlay = 1

################################
# UIImage+SVG related
################################
SVGImageCache = ObjCClass('SVGImageCache')

CollapsableTableView = ObjCClass('CollapsableTableView')
CollapsableSectionHeaderView = ObjCClass('CollapsableSectionHeaderView')

ForwardingDelegate = ObjCClass('ForwardingDelegate')

# Custom activity indicator created by Calin
CCActivityIndicator = ObjCClass('CCActivityIndicator')

# Some of the below are found in ViewForIB.h, but also in misc other .h files (search project if you really want to track them down)
CustomViewController = ObjCClass('CustomViewController')
CustomNavController = ObjCClass('CustomNavController')
AddrConvBase = ObjCClass('AddrConvBase')
NewContactBase = ObjCClass('NewContactBase')
SendBase = ObjCClass('SendBase')
TxDetailBase = ObjCClass('TxDetailBase')
WalletsNavBase = ObjCClass('WalletsNavBase')
WalletsVCBase = ObjCClass('WalletsVCBase')
WalletsDrawerVCBase = ObjCClass('WalletsDrawerVCBase')
TxHistoryHelperBase = ObjCClass('TxHistoryHelperBase')
TxHistoryCell = ObjCClass('TxHistoryCell')
TxInputsOutputsTVCBase = ObjCClass('TxInputsOutputsTVCBase')
ReqTVDBase = ObjCClass('ReqTVDBase')
ContactsVCBase = ObjCClass('ContactsVCBase')
ContactDetailVCBase = ObjCClass('ContactDetailVCBase')
AddressesVCBase = ObjCClass('AddressesVCBase')
ComboDrawerPicker = ObjCClass('ComboDrawerPicker')
AddressDetailBase = ObjCClass('AddressDetailBase')
CoinsCell = ObjCClass('CoinsCell')
CoinsDetailBase = ObjCClass('CoinsDetailBase')
ECTextViewDelegate = ObjCClass('ECTextViewDelegate')
LinkLabel = ObjCClass('LinkLabel')
PleaseWaitVC = ObjCClass('PleaseWaitVC')
NewWalletNavBase = ObjCClass('NewWalletNavBase')
NewWalletVCBase = ObjCClass('NewWalletVCBase')
NewWalletSeedBase = ObjCClass('NewWalletSeedBase')
KeyboardVC = ObjCClass('KeyboardVC')
SuggestionButton = ObjCClass('SuggestionButton')
NewWalletMenuBase = ObjCClass('NewWalletMenuBase')
OnBoardingWizardBase = ObjCClass('OnBoardingWizardBase')
OnBoardingMenuBase = ObjCClass('OnBoardingMenuBase')
OnBoardingPageBase = ObjCClass('OnBoardingPageBase')
Import1Base = ObjCClass('Import1Base')
Import2Base = ObjCClass('Import2Base')
PrivateKeyDialogBase = ObjCClass('PrivateKeyDialogBase')
SignDecryptBase = ObjCClass('SignDecryptBase')
ReceiveBase = ObjCClass('ReceiveBase')
SeedDisplayBase = ObjCClass('SeedDisplayBase')
KeyInterface = ObjCClass('KeyInterface')
CrashReporterBase = ObjCClass('CrashReporterBase')
