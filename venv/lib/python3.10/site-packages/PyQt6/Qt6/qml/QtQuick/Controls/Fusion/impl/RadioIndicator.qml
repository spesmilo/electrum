// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.Fusion
import QtQuick.Controls.Fusion.impl

Rectangle {
    id: indicator

    property Item control
    readonly property color pressedColor: Fusion.mergedColors(control.palette.base, control.palette.windowText, 85)
    readonly property color checkMarkColor: Qt.darker(control.palette.text, 1.2)

    implicitWidth: 14
    implicitHeight: 14

    radius: width / 2
    color: control.down ? indicator.pressedColor : Qt.lighter(control.palette.base, 1.75)
    border.color: control.visualFocus ? Fusion.highlightedOutline(control.palette)
                                      : Fusion.highContrast
                                      ? Fusion.outline(control.palette)
                                      : Qt.darker(control.palette.window, 1.5)

    Rectangle {
        y: 1
        width: parent.width
        height: parent.height - 1
        radius: width / 2
        color: "transparent"
        border.color: Fusion.topShadow
        visible: indicator.control.enabled && !indicator.control.down
    }

    Rectangle {
        x: (parent.width - width) / 2
        y: (parent.height - height) / 2
        width: parent.width / 2.32
        height: parent.height / 2.32
        radius: width / 2
        color: Color.transparent(indicator.checkMarkColor, 180 / 255)
        border.color: Color.transparent(indicator.checkMarkColor, 200 / 255)
        visible: indicator.control.checked
    }
}
