// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.Universal

T.RangeSlider {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            first.implicitHandleWidth + leftPadding + rightPadding,
                            second.implicitHandleWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             first.implicitHandleHeight + topPadding + bottomPadding,
                             second.implicitHandleHeight + topPadding + bottomPadding)

    padding: 6

    first.handle: Rectangle {
        implicitWidth: control.horizontal ? 8 : 24
        implicitHeight: control.horizontal ? 24 : 8

        x: control.leftPadding + (control.horizontal ? control.first.visualPosition * (control.availableWidth - width) : (control.availableWidth - width) / 2)
        y: control.topPadding + (control.horizontal ? (control.availableHeight - height) / 2 : control.first.visualPosition * (control.availableHeight - height))

        radius: 4
        color: control.first.pressed ? control.Universal.chromeHighColor :
               control.first.hovered ? control.Universal.chromeAltLowColor :
               control.enabled ? control.Universal.accent : control.Universal.chromeDisabledHighColor
    }

    second.handle: Rectangle {
        implicitWidth: control.horizontal ? 8 : 24
        implicitHeight: control.horizontal ? 24 : 8

        x: control.leftPadding + (control.horizontal ? control.second.visualPosition * (control.availableWidth - width) : (control.availableWidth - width) / 2)
        y: control.topPadding + (control.horizontal ? (control.availableHeight - height) / 2 : control.second.visualPosition * (control.availableHeight - height))

        radius: 4
        color: control.second.pressed ? control.Universal.chromeHighColor :
               control.second.hovered ? control.Universal.chromeAltLowColor :
               control.enabled ? control.Universal.accent : control.Universal.chromeDisabledHighColor
    }

    background: Item {
        implicitWidth: control.horizontal ? 200 : 18
        implicitHeight: control.horizontal ? 18 : 200

        x: control.leftPadding + (control.horizontal ? 0 : (control.availableWidth - width) / 2)
        y: control.topPadding + (control.horizontal ? (control.availableHeight - height) / 2 : 0)
        width: control.horizontal ? control.availableWidth : implicitWidth
        height: control.horizontal ? implicitHeight : control.availableHeight

        scale: control.horizontal && control.mirrored ? -1 : 1

        Rectangle {
            x: control.horizontal ? 0 : (parent.width - width) / 2
            y: control.horizontal ? (parent.height - height) / 2 : 0
            width: control.horizontal ? parent.width : 2 // SliderBackgroundThemeHeight
            height: control.vertical ? parent.height : 2 // SliderBackgroundThemeHeight

            color: enabled && control.hovered && !control.pressed ? control.Universal.baseMediumColor :
                   control.enabled ? control.Universal.baseMediumLowColor : control.Universal.chromeDisabledHighColor
        }

        Rectangle {
            x: control.horizontal ? control.first.position * parent.width : (parent.width - width) / 2
            y: control.horizontal ? (parent.height - height) / 2 : control.second.visualPosition * parent.height
            width: control.horizontal ? control.second.position * parent.width - control.first.position * parent.width : 2 // SliderBackgroundThemeHeight
            height: control.vertical ? control.second.position * parent.height - control.first.position * parent.height : 2 // SliderBackgroundThemeHeight

            color: control.enabled ? control.Universal.accent : control.Universal.chromeDisabledHighColor
        }
    }
}
