// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Templates as T

T.RangeSlider {
    id: control

    readonly property color handleBorderColor: {
        if (activeFocus)
            return palette.highlight
        else if (Qt.styleHints.accessibility.contrastPreference !== Qt.HighContrast)
            return enabled ? palette.mid : palette.midlight
        else
            return enabled ? palette.windowText : palette.mid
    }

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            first.implicitHandleWidth + leftPadding + rightPadding,
                            second.implicitHandleWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             first.implicitHandleHeight + topPadding + bottomPadding,
                             second.implicitHandleHeight + topPadding + bottomPadding)

    padding: 6

    first.handle: Rectangle {
        x: control.leftPadding + (control.horizontal ? control.first.visualPosition * (control.availableWidth - width) : (control.availableWidth - width) / 2)
        y: control.topPadding + (control.horizontal ? (control.availableHeight - height) / 2 : control.first.visualPosition * (control.availableHeight - height))
        implicitWidth: 28
        implicitHeight: 28
        radius: width / 2
        border.width: activeFocus ? 2 : 1
        border.color: control.handleBorderColor
        color: control.first.pressed ? control.palette.light : control.palette.window
    }

    second.handle: Rectangle {
        x: control.leftPadding + (control.horizontal ? control.second.visualPosition * (control.availableWidth - width) : (control.availableWidth - width) / 2)
        y: control.topPadding + (control.horizontal ? (control.availableHeight - height) / 2 : control.second.visualPosition * (control.availableHeight - height))
        implicitWidth: 28
        implicitHeight: 28
        radius: width / 2
        border.width: activeFocus ? 2 : 1
        border.color: control.handleBorderColor
        color: control.second.pressed ? control.palette.light : control.palette.window
    }

    background: Rectangle {
        x: control.leftPadding + (control.horizontal ? 0 : (control.availableWidth - width) / 2)
        y: control.topPadding + (control.horizontal ? (control.availableHeight - height) / 2 : 0)
        implicitWidth: control.horizontal ? 200 : 6
        implicitHeight: control.horizontal ? 6 : 200
        width: control.horizontal ? control.availableWidth : implicitWidth
        height: control.horizontal ? implicitHeight : control.availableHeight
        radius: 3
        color: control.palette.midlight
        scale: control.horizontal && control.mirrored ? -1 : 1
        border.width: Qt.styleHints.accessibility.contrastPreference === Qt.HighContrast ? 1 : 0
        border.color: enabled ? control.palette.dark : control.palette.mid

        Rectangle {
            x: control.horizontal ? control.first.position * parent.width + 3 : 0
            y: control.horizontal ? 0 : control.second.visualPosition * parent.height + 3
            width: control.horizontal ? control.second.position * parent.width - control.first.position * parent.width - 6 : 6
            height: control.horizontal ? 6 : control.second.position * parent.height - control.first.position * parent.height - 6

            color: control.palette.dark
        }
    }
}
