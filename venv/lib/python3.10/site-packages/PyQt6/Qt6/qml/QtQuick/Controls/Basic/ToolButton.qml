// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Templates as T

T.ToolButton {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    padding: 6
    spacing: 6

    icon.width: 24
    icon.height: 24
    icon.color: visualFocus ? control.palette.highlight : control.palette.buttonText

    contentItem: IconLabel {
        spacing: control.spacing
        mirrored: control.mirrored
        display: control.display

        icon: control.icon
        text: control.text
        font: control.font
        color: control.visualFocus ? control.palette.highlight : control.palette.buttonText
    }

    background: Rectangle {
        implicitWidth: 40
        implicitHeight: 40

        opacity: Qt.styleHints.accessibility.contrastPreference === Qt.HighContrast || control.down ? 1.0 : 0.5
        color: control.down || control.checked || control.highlighted ? control.palette.mid : control.palette.button

        border.color: {
            if (control.visualFocus)
                return control.palette.highlight
            else if (Qt.styleHints.accessibility.contrastPreference === Qt.HighContrast)
                return Color.blend(control.palette.buttonText, control.palette.button,
                                   control.enabled ? 0.0 : 0.8)
            else
                return control.palette.windowText
        }
        border.width: control.visualFocus ? 2 :
                      Qt.styleHints.accessibility.contrastPreference === Qt.HighContrast ? 1 : 0
    }
}
