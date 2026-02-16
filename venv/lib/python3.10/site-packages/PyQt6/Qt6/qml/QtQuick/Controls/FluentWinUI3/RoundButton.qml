// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.FluentWinUI3.impl
import QtQuick.Templates as T

T.RoundButton {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    spacing: __config.spacing || 0

    topPadding: __config.topPadding || 0
    bottomPadding: __config.bottomPadding || 0
    leftPadding: __config.leftPadding || 0
    rightPadding: __config.rightPadding || 0

    icon.width: __config.icon.width
    icon.height: __config.icon.height
    icon.color: __buttonText

    readonly property color __buttonText: {
        if (Application.styleHints.accessibility.contrastPreference === Qt.HighContrast) {
            return (control.enabled && ((control.flat && (control.down || control.hovered))
                || ((control.highlighted || control.checked) && !control.down)))
                ? control.palette.button
                : control.enabled && (control.hovered || control.down)
                ? control.palette.highlight
                : control.palette.buttonText
        }
        if (control.down) {
            return (control.checked || control.highlighted)
                ? Application.styleHints.colorScheme == Qt.Light
                    ? Color.transparent("white", 0.7) : Color.transparent("black", 0.5)
                : (Application.styleHints.colorScheme === Qt.Light
                    ? Color.transparent(control.palette.buttonText, 0.62)
                    : Color.transparent(control.palette.buttonText, 0.7725))
        } else if (control.checked || control.highlighted) {
            return (Application.styleHints.colorScheme === Qt.Dark && !control.enabled)
                ? Color.transparent("white", 0.5302)
                : (Application.styleHints.colorScheme === Qt.Dark ? "black" : "white")
        } else {
            return control.palette.buttonText
        }
    }

    readonly property string __currentState: [
        (control.checked || control.highlighted) && "checked",
        !control.enabled && "disabled",
        control.enabled && !control.down && control.hovered && "hovered",
        control.down && "pressed"
    ].filter(Boolean).join("_") || "normal"
    readonly property var __config: (control.flat && Config.controls.flatbutton
        ? Config.controls.flatbutton[__currentState]
        : Config.controls.button[__currentState]) || {}

    readonly property Item __focusFrameTarget: control

    contentItem: IconLabel {
        spacing: control.spacing
        mirrored: control.mirrored
        display: control.display

        icon: control.icon
        text: control.text
        font: control.font
        color: control.icon.color
    }

    background: ButtonBackground {
        control: control
        implicitHeight: control.__config.background.height
        implicitWidth: implicitWidth
        radius: control.radius
    }
}

