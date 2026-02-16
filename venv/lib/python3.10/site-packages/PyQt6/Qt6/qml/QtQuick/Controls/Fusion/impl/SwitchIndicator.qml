// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Fusion
import QtQuick.Controls.Fusion.impl

Rectangle {
    id: indicator

    property T.AbstractButton control
    readonly property color pressedColor: Fusion.mergedColors(control.palette.base, control.palette.windowText, 85)
    readonly property color checkMarkColor: Qt.darker(control.palette.text, 1.2)

    implicitWidth: 40
    implicitHeight: 16

    radius: 2
    border.color: Fusion.outline(control.palette)

    gradient: Gradient {
        GradientStop {
            position: 0
            color: Qt.darker(Fusion.grooveColor(indicator.control.palette), 1.1)
        }
        GradientStop {
            position: 1
            color: Qt.lighter(Fusion.grooveColor(indicator.control.palette), 1.1)
        }
    }

    Rectangle {
        x: indicator.control.mirrored ? handle.x : 0
        width: indicator.control.mirrored ? parent.width - handle.x : handle.x + handle.width
        height: parent.height

        opacity: indicator.control.checked ? 1 : 0
        Behavior on opacity {
            enabled: !indicator.control.down
            NumberAnimation { duration: 80 }
        }

        radius: 2
        border.color: Qt.darker(Fusion.highlightedOutline(indicator.control.palette), 1.1)
        border.width: indicator.control.enabled ? 1 : 0

        gradient: Gradient {
            GradientStop {
                position: 0
                color: Qt.alpha(indicator.control.palette.active.highlight,
                                indicator.Window ? indicator.Window.active ? 1 : 0.5 : 1)
            }
            GradientStop {
                position: 1
                color: Qt.alpha(Qt.lighter(indicator.control.palette.active.highlight, 1.2),
                                indicator.Window ? indicator.Window.active ? 1 : 0.5 : 1)
            }
        }
    }

    Rectangle {
        id: handle
        x: Math.max(0, Math.min(parent.width - width, indicator.control.visualPosition * parent.width - (width / 2)))
        y: (parent.height - height) / 2
        width: 20
        height: 16
        radius: 2

        gradient: Gradient {
            GradientStop {
                position: 0
                color: Fusion.gradientStart(Fusion.buttonColor(indicator.control.palette,
                    indicator.control.visualFocus, indicator.control.pressed, indicator.enabled && indicator.control.hovered))
            }
            GradientStop {
                position: 1
                color: Fusion.gradientStop(Fusion.buttonColor(indicator.control.palette,
                    indicator.control.visualFocus, indicator.control.pressed, indicator.enabled && indicator.control.hovered))
            }
        }
        border.width: 1
        border.color: "transparent"

        Rectangle {
            width: parent.width
            height: parent.height
            border.color: indicator.control.visualFocus ? Fusion.highlightedOutline(indicator.control.palette) : Fusion.outline(indicator.control.palette)
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

        Behavior on x {
            enabled: !indicator.control.down
            SmoothedAnimation { velocity: 200 }
        }
    }
}
