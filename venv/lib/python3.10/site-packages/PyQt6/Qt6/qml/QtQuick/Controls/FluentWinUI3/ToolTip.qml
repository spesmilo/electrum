// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Templates as T
import QtQuick.Effects

T.ToolTip {
    id: control

    x: parent ? (parent.width - implicitWidth) / 2 : 0
    y: -implicitHeight

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    padding: 8

    topInset: -8
    bottomInset: -8
    leftInset: -8
    rightInset: -8

    closePolicy: T.Popup.CloseOnEscape | T.Popup.CloseOnPressOutsideParent | T.Popup.CloseOnReleaseOutsideParent

    contentItem: Text {
        text: control.text
        font: control.font
        wrapMode: Text.Wrap
        color: control.palette.toolTipText
    }

    background: Item {
        MultiEffect {
            x: -control.leftInset
            y: -control.topInset
            width: source.width
            height: source.height
            source: Rectangle {
                width: control.background.width + control.leftInset + control.rightInset
                implicitHeight: 30
                height: control.background.height + control.topInset + control.bottomInset
                color: control.palette.toolTipBase
                border.width: 1
                border.color: Application.styleHints.colorScheme === Qt.Light ? control.palette.midlight : Color.transparent(control.palette.shadow, 0.2)
                radius: 4
            }
            shadowOpacity: Application.styleHints.colorScheme === Qt.Light ? 0.14 : 0.26
            shadowColor: control.palette.shadow
            shadowEnabled: true
            shadowHorizontalOffset: 0
            shadowVerticalOffset: 4
            blurMax: 32
        }
    }
}
