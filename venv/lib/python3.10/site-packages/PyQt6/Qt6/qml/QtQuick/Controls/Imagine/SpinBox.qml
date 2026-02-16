// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.Imagine
import QtQuick.Controls.Imagine.impl

T.SpinBox {
    id: control

    // Note: the width of the indicators are calculated into the padding
    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            contentItem.implicitWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             up.implicitIndicatorHeight, down.implicitIndicatorHeight)

    topPadding: background ? background.topPadding : 0
    leftPadding: (background ? background.leftPadding : 0) + (control.mirrored ? (up.indicator ? up.indicator.width : 0) : (down.indicator ? down.indicator.width : 0))
    rightPadding: (background ? background.rightPadding : 0) + (control.mirrored ? (down.indicator ? down.indicator.width : 0) : (up.indicator ? up.indicator.width : 0))
    bottomPadding: background ? background.bottomPadding : 0

    topInset: background ? -background.topInset || 0 : 0
    leftInset: background ? -background.leftInset || 0 : 0
    rightInset: background ? -background.rightInset || 0 : 0
    bottomInset: background ? -background.bottomInset || 0 : 0

    validator: IntValidator {
        locale: control.locale.name
        bottom: Math.min(control.from, control.to)
        top: Math.max(control.from, control.to)
    }

    contentItem: TextInput {
        z: 2
        text: control.displayText
        opacity: control.enabled ? 1 : 0.3

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

        NinePatchImage {
            z: -1
            width: control.width
            height: control.height
            visible: control.editable

            source: Imagine.url + "spinbox-editor"
            NinePatchImageSelector on source {
                states: [
                    {"disabled": !control.enabled},
                    {"focused": control.activeFocus},
                    {"mirrored": control.mirrored},
                    {"hovered": control.enabled && control.hovered}
                ]
            }
        }
    }

    up.indicator: NinePatchImage {
        x: control.mirrored ? 0 : control.width - width
        height: control.height

        source: Imagine.url + "spinbox-indicator"
        NinePatchImageSelector on source {
            states: [
                {"up": true},
                {"disabled": !control.up.indicator.enabled},
                {"editable": control.editable},
                {"pressed": control.up.pressed},
                {"focused": control.activeFocus},
                {"mirrored": control.mirrored},
                {"hovered": control.up.hovered}
            ]
        }
    }

    down.indicator: NinePatchImage {
        x: control.mirrored ? control.width - width : 0
        height: control.height

        source: Imagine.url + "spinbox-indicator"
        NinePatchImageSelector on source {
            states: [
                {"down": true},
                {"disabled": !control.down.indicator.enabled},
                {"editable": control.editable},
                {"pressed": control.down.pressed},
                {"focused": control.activeFocus},
                {"mirrored": control.mirrored},
                {"hovered": control.down.hovered}
            ]
        }
    }

    background: NinePatchImage {
        source: Imagine.url + "spinbox-background"
        NinePatchImageSelector on source {
            states: [
                {"disabled": !control.enabled},
                {"editable": control.editable},
                {"focused": control.activeFocus},
                {"mirrored": control.mirrored},
                {"hovered": control.enabled && control.hovered}
            ]
        }
    }
}
