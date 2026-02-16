// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.FluentWinUI3.impl

T.DelayButton {
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
            return (control.checked)
                ? Application.styleHints.colorScheme == Qt.Light
                    ? Color.transparent("white", 0.7) : Color.transparent("black", 0.5)
                : (Application.styleHints.colorScheme === Qt.Light
                    ? Color.transparent(control.palette.buttonText, 0.62)
                    : Color.transparent(control.palette.buttonText, 0.7725))
        } else if (control.checked) {
            return (Application.styleHints.colorScheme === Qt.Dark && !control.enabled)
                ? Color.transparent("white", 0.5302)
                : (Application.styleHints.colorScheme === Qt.Dark ? "black" : "white")
        } else {
            return control.palette.buttonText
        }
    }

    readonly property string __currentState: [
        control.checked && "checked",
        !control.enabled && "disabled",
        control.enabled && !control.down && control.hovered && "hovered",
        control.down && "pressed"
    ].filter(Boolean).join("_") || "normal"
    readonly property var __config: Config.controls.button[__currentState] || {}

    readonly property Item __focusFrameTarget: control

    transition: Transition {
        NumberAnimation {
            duration: control.delay * (control.pressed ? 1.0 - control.progress : 0.3 * control.progress)
        }
    }

    contentItem: ItemGroup {
        ClippedText {
            clip: control.progress > 0
            clipX: -control.leftPadding + control.progress * control.width
            clipWidth: (1.0 - control.progress) * control.width
            visible: control.progress < 1

            text: control.text
            font: control.font
            color: control.icon.color
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            elide: Text.ElideRight
        }

        ClippedText {
            clip: control.progress > 0
            clipX: -control.leftPadding
            clipWidth: control.progress * control.width
            visible: control.progress > 0

            text: control.text
            font: control.font
            color: control.icon.color
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            elide: Text.ElideRight
        }
    }

    background: ButtonBackground {
        control: control
        implicitHeight: control.__config.background.height
        implicitWidth: control.__config.background.width
        radius: control.__config.background.topOffset
        subtle: false

        Rectangle {
            width: control.progress * parent.width
            height: parent.height
            radius: parent.radius
            color: control.down ? control.palette.accent : "transparent"
            visible: !control.checked && control.enabled
        }
    }
}
