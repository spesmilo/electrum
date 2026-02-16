// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Fusion
import QtQuick.Controls.Fusion.impl

T.SpinBox {
    id: control

    // Note: the width of the indicators are calculated into the padding
    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            contentItem.implicitWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             up.implicitIndicatorHeight + down.implicitIndicatorHeight)

    padding: 4
    leftPadding: padding + (control.mirrored ? (up.indicator ? up.indicator.width : 0) : 0)
    rightPadding: padding + (!control.mirrored ? (up.indicator ? up.indicator.width : 0) : 0)

    validator: IntValidator {
        locale: control.locale.name
        bottom: Math.min(control.from, control.to)
        top: Math.max(control.from, control.to)
    }

    contentItem: TextInput {
        z: 2
        text: control.displayText

        font: control.font
        color: control.palette.text
        selectionColor: control.palette.highlight
        selectedTextColor: control.palette.highlightedText
        horizontalAlignment: Qt.AlignHCenter
        verticalAlignment: Qt.AlignVCenter

        readOnly: !control.editable
        validator: control.validator
        inputMethodHints: control.inputMethodHints
        clip: width < implicitWidth
    }

    up.indicator: PaddedRectangle {
        x: control.mirrored ? 1 : control.width - width - 1
        y: 1
        height: control.height / 2 - 1
        implicitWidth: 16
        implicitHeight: 10

        radius: 1.7
        clip: true
        topPadding: -2
        leftPadding: -2
        color: control.up.pressed ? Fusion.buttonColor(control.palette, false, true, true) : "transparent"

        ColorImage {
            scale: -1
            width: parent.width
            height: parent.height
            opacity: enabled ? 1.0 : 0.5
            color: control.palette.buttonText
            source: "qrc:/qt-project.org/imports/QtQuick/Controls/Fusion/images/arrow.png"
            fillMode: Image.Pad
        }
    }

    down.indicator: PaddedRectangle {
        x: control.mirrored ? 1 : control.width - width - 1
        y: control.height - height - 1
        height: control.height / 2 - 1
        implicitWidth: 16
        implicitHeight: 10

        radius: 1.7
        clip: true
        topPadding: -2
        leftPadding: -2
        color: control.down.pressed ? Fusion.buttonColor(control.palette, false, true, true) : "transparent"

        ColorImage {
            width: parent.width
            height: parent.height
            opacity: enabled ? 1.0 : 0.5
            color: control.palette.buttonText
            source: "qrc:/qt-project.org/imports/QtQuick/Controls/Fusion/images/arrow.png"
            fillMode: Image.Pad
        }
    }

    background: Rectangle {
        implicitWidth: 120
        implicitHeight: 24

        radius: 2
        color: control.palette.base
        border.color: control.activeFocus ? Fusion.highlightedOutline(control.palette) : Fusion.outline(control.palette)

        Rectangle {
            x: 2
            y: 1
            width: parent.width - 4
            height: 1
            color: Fusion.topShadow
        }

        Rectangle {
            x: control.mirrored ? 1 : parent.width - width - 1
            y: 1
            width: Math.max(control.up.indicator ? control.up.indicator.width : 0,
                            control.down.indicator ? control.down.indicator.width : 0) + 1
            height: parent.height - 2

            radius: 2
            gradient: Gradient {
                GradientStop {
                    position: 0
                    color: Fusion.gradientStart(Fusion.buttonColor(control.palette, control.visualFocus, false, control.up.hovered || control.down.hovered))
                }
                GradientStop {
                    position: 1
                    color: Fusion.gradientStop(Fusion.buttonColor(control.palette, control.visualFocus, false, control.up.hovered || control.down.hovered))
                }
            }

            Rectangle {
                x: control.mirrored ? parent.width - 1 : 0
                height: parent.height
                width: 1
                color: Fusion.outline(control.palette)
            }
        }

        Rectangle {
            x: 1; y: 1
            width: parent.width - 2
            height: parent.height - 2
            color: "transparent"
            border.color: Color.transparent(Fusion.highlightedOutline(control.palette), 40 / 255)
            visible: control.activeFocus
            radius: 1.7
        }
    }
}
