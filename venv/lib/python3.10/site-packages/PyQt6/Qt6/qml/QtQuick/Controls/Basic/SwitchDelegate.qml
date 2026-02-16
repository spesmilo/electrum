// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl

T.SwitchDelegate {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             implicitIndicatorHeight + topPadding + bottomPadding)

    padding: 12
    spacing: 12

    icon.width: 24
    icon.height: 24
    icon.color: control.palette.text

    indicator: PaddedRectangle {
        implicitWidth: 56
        implicitHeight: 28

        x: control.text ? (control.mirrored ? control.leftPadding : control.width - width - control.rightPadding) : control.leftPadding + (control.availableWidth - width) / 2
        y: control.topPadding + (control.availableHeight - height) / 2

        radius: 8
        leftPadding: 0
        rightPadding: 0
        padding: (height - 16) / 2
        color: control.checked ? control.palette.dark : control.palette.midlight
        border.width: Qt.styleHints.accessibility.contrastPreference === Qt.HighContrast ? 1 : 0
        border.color: Color.blend(control.palette.dark, control.palette.base, enabled ? 0.0 : 0.5)

        Rectangle {
            x: Math.max(0, Math.min(parent.width - width, control.visualPosition * parent.width - (width / 2)))
            y: (parent.height - height) / 2
            width: 28
            height: 28
            radius: 16
            color: control.down ? control.palette.light : control.palette.window
            border.width: control.visualFocus ? 2 : 1
            border.color: {
                if (control.visualFocus)
                    return control.palette.highlight;
                else if (Qt.styleHints.accessibility.contrastPreference !== Qt.HighContrast)
                    return control.enabled ? control.palette.mid : control.palette.midlight
                else
                    return Color.blend(control.palette.dark, control.palette.base,
                                       control.enabled ? 0.0 : 0.5)
            }

            Behavior on x {
                enabled: !control.down
                SmoothedAnimation { velocity: 200 }
            }
        }
    }

    contentItem: IconLabel {
        leftPadding: control.mirrored ? control.indicator.width + control.spacing : 0
        rightPadding: !control.mirrored ? control.indicator.width + control.spacing : 0

        spacing: control.spacing
        mirrored: control.mirrored
        display: control.display
        alignment: control.display === IconLabel.IconOnly || control.display === IconLabel.TextUnderIcon ? Qt.AlignCenter : Qt.AlignLeft

        icon: control.icon
        text: control.text
        font: control.font
        color: control.palette.text
    }

    background: Rectangle {
        implicitWidth: 100
        implicitHeight: 40
        visible: control.down || control.highlighted
        color: control.down ? control.palette.midlight : control.palette.light
    }
}
