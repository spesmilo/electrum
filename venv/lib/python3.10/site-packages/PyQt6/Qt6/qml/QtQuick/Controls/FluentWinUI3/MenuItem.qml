// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl

T.MenuItem {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             implicitIndicatorHeight + topPadding + bottomPadding)

    leftPadding: 12
    rightPadding: 12
    topPadding: 3
    bottomPadding: 3
    spacing: 6

    icon.width: 16
    icon.height: 16
    icon.color: control.palette.text

    implicitTextPadding: control.checkable && control.indicator ? control.indicator.width + control.spacing : 0

    contentItem: IconLabel {
        readonly property real arrowPadding: control.subMenu && control.arrow ? control.arrow.width + control.spacing : 0
        leftPadding: !control.mirrored ? control.textPadding : arrowPadding
        rightPadding: control.mirrored ? control.textPadding : arrowPadding

        spacing: control.spacing
        mirrored: control.mirrored
        display: control.display
        alignment: Qt.AlignLeft

        icon: control.icon
        text: control.text
        font: control.font
        color: control.icon.color
    }

    arrow: ColorImage {
        x: control.mirrored ? control.padding : control.width - width - control.padding
        y: control.topPadding + (control.availableHeight - height) / 2
        width: 20

        visible: control.subMenu
        rotation: control.mirrored ? -180 : 0
        color: control.palette.text
        source: Qt.resolvedUrl("icons/menuarrow.png")
        fillMode: Image.Pad
    }

    indicator: Item {
        implicitWidth: 14
        implicitHeight: 10

        x: control.mirrored ? control.width - width - control.rightPadding : control.leftPadding
        y: control.topPadding + (control.availableHeight - height) / 2

        visible: control.checkable

        ColorImage {
            y: (parent.height - height) / 2
            color: control.palette.text
            source: Qt.resolvedUrl("icons/checkmark.png")
            visible: control.checkState === Qt.Checked
                    || (control.checked && control.checkState === undefined)
        }
    }

    background: Rectangle {
        implicitWidth: 200
        implicitHeight: 30
        radius: 4

        readonly property real alpha: control.down
            ? Application.styleHints.colorScheme === Qt.Light ? 0.0241 : 0.0419
            : control.hovered ? Application.styleHints.colorScheme === Qt.Light ? 0.0373 : 0.0605 : 0

        color: Application.styleHints.colorScheme === Qt.Light ? Qt.rgba(0, 0, 0, alpha) : Qt.rgba(1, 1, 1, alpha)
        visible: control.down || control.highlighted
    }
}
