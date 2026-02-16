// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.Fusion
import QtQuick.Controls.Fusion.impl

Rectangle {
    id: handle

    property var palette
    property bool pressed
    property bool hovered
    property bool vertical
    property bool visualFocus

    implicitWidth: 13
    implicitHeight: 13

    gradient: Gradient {
        GradientStop {
            position: 0
            color: Fusion.gradientStart(Fusion.buttonColor(handle.palette, handle.visualFocus,
                handle.pressed, handle.enabled && handle.hovered))
        }
        GradientStop {
            position: 1
            color: Fusion.gradientStop(Fusion.buttonColor(handle.palette, handle.visualFocus,
                handle.pressed, handle.enabled && handle.hovered))
        }
    }
    rotation: handle.vertical ? -90 : 0
    border.width: 1
    border.color: "transparent"
    radius: 2

    Rectangle {
        width: parent.width
        height: parent.height
        border.color: handle.visualFocus ? Fusion.highlightedOutline(handle.palette) : Fusion.outline(handle.palette)
        color: "transparent"
        radius: 2

        Rectangle {
            x: 1; y: 1
            width: parent.width - 2
            height: parent.height - 2
            border.color: Fusion.innerContrastLine
            color: "transparent"
            radius: 2
        }
    }
}
