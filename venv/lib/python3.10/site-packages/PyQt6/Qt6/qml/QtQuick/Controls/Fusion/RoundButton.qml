// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Fusion
import QtQuick.Controls.Fusion.impl

T.RoundButton {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    padding: 6
    spacing: 6

    icon.width: 16
    icon.height: 16
    icon.color: control.checked || control.highlighted ? control.palette.brightText :
                control.flat && !control.down ? (control.visualFocus ? control.palette.highlight : control.palette.windowText) : control.palette.buttonText

    contentItem: IconLabel {
        spacing: control.spacing
        mirrored: control.mirrored
        display: control.display

        icon: control.icon
        text: control.text
        font: control.font
        color: control.palette.buttonText
    }

    background: Rectangle {
        implicitWidth: 32
        implicitHeight: 32
        visible: !control.flat || control.down || control.checked

        gradient: Gradient {
            GradientStop {
                position: 0
                color: control.down || control.checked
                    ? Fusion.buttonColor(control.palette, control.highlighted, control.down || control.checked, control.enabled && control.hovered)
                    : Fusion.gradientStart(Fusion.buttonColor(control.palette, control.highlighted, control.down, control.enabled && control.hovered))
            }
            GradientStop {
                position: 1
                color: control.down || control.checked
                    ? Fusion.buttonColor(control.palette, control.highlighted, control.down || control.checked, control.enabled && control.hovered)
                    : Fusion.gradientStop(Fusion.buttonColor(control.palette, control.highlighted, control.down, control.enabled && control.hovered))
            }
        }

        radius: control.radius
        border.color: Fusion.buttonOutline(control.palette, control.highlighted || control.visualFocus, control.enabled)

        Rectangle {
            x: 1; y: 1
            width: parent.width - 2
            height: parent.height - 2
            border.color: Fusion.innerContrastLine
            color: "transparent"
            radius: control.radius
        }
    }
}
