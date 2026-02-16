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
    property real baseLightness: 1.6

    readonly property color pressedColor: Fusion.mergedColors(control.palette.base, control.palette.windowText, 85)
    readonly property color checkMarkColor: Qt.darker(control.palette.text, 1.2)

    implicitWidth: 14
    implicitHeight: 14

    color: control.down ? indicator.pressedColor : Qt.lighter(control.palette.base, baseLightness)
    border.color: control.visualFocus ? Fusion.highlightedOutline(control.palette)
                                      : Qt.lighter(Fusion.outline(control.palette), 1.1)

    Rectangle {
        x: 1; y: 1
        width: parent.width - 2
        height: 1
        color: Fusion.topShadow
        visible: indicator.control.enabled && !indicator.control.down
    }

    ColorImage {
        x: (parent.width - width) / 2
        y: (parent.height - height) / 2
        color: Color.transparent(indicator.checkMarkColor, 210 / 255)
        source: "qrc:/qt-project.org/imports/QtQuick/Controls/Fusion/images/checkmark.png"
        visible: indicator.control.checkState === Qt.Checked || (indicator.control.checked && indicator.control.checkState === undefined)
    }

    Rectangle {
        x: 3; y: 3
        width: parent.width - 6
        height: parent.width - 6

        visible: indicator.control.checkState === Qt.PartiallyChecked

        gradient: Gradient {
            GradientStop {
                position: 0
                color: Color.transparent(indicator.checkMarkColor, 80 / 255)
            }
            GradientStop {
                position: 1
                color: Color.transparent(indicator.checkMarkColor, 140 / 255)
            }
        }
        border.color: Color.transparent(indicator.checkMarkColor, 180 / 255)
    }
}
