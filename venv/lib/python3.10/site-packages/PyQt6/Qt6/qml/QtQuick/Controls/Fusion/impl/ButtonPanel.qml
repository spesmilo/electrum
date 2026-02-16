// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.Fusion
import QtQuick.Controls.Fusion.impl

Rectangle {
    id: panel

    property Item control
    property bool highlighted: control.highlighted

    visible: !control.flat || control.down || control.checked

    color: Fusion.buttonColor(control.palette, panel.highlighted, control.down || control.checked,
        enabled && control.hovered)
    gradient: control.down || control.checked ? null : buttonGradient

    Gradient {
        id: buttonGradient
        GradientStop {
            position: 0
            color: Fusion.gradientStart(Fusion.buttonColor(panel.control.palette, panel.highlighted,
                panel.control.down, panel.enabled && panel.control.hovered))
        }
        GradientStop {
            position: 1
            color: Fusion.gradientStop(Fusion.buttonColor(panel.control.palette, panel.highlighted,
                panel.control.down, panel.enabled && panel.control.hovered))
        }
    }

    radius: 2
    border.color: Fusion.buttonOutline(control.palette, panel.highlighted || control.visualFocus, control.enabled)

    Rectangle {
        x: 1; y: 1
        width: parent.width - 2
        height: parent.height - 2
        border.color: Fusion.innerContrastLine
        color: "transparent"
        radius: 2
    }
}
