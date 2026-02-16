// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl

T.SwipeDelegate {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             implicitIndicatorHeight + topPadding + bottomPadding)

    spacing: __config.spacing || 0

    topPadding: __config.topPadding || 0
    leftPadding: __config.leftPadding || 0
    rightPadding: __config.rightPadding || 0
    bottomPadding: __config.bottomPadding || 0

    icon.width: 16
    icon.height: 16
    icon.color: control.down ? __pressedText : control.palette.buttonText

    readonly property color __pressedText: Application.styleHints.colorScheme === Qt.Light
        ? Color.transparent(control.palette.buttonText, 0.62)
        : Color.transparent(control.palette.buttonText, 0.7725)
    readonly property string __currentState: [
        !control.enabled && "disabled",
        control.highlighted && "highlighted",
        control.enabled && !control.down && control.hovered && "hovered",
        control.down && "pressed"
    ].filter(Boolean).join("_") || "normal"
    readonly property var __config: Config.controls.itemdelegate[__currentState] || {}

    readonly property Item __focusFrameTarget: control

    swipe.transition: Transition { SmoothedAnimation { duration: 167; easing.type: Easing.OutCubic } }

    contentItem: IconLabel {
        spacing: control.spacing
        mirrored: control.mirrored
        display: control.display
        alignment: control.display === IconLabel.IconOnly || control.display === IconLabel.TextUnderIcon ? Qt.AlignCenter : Qt.AlignLeft

        icon: control.icon
        text: control.text
        font: control.font
        color: control.icon.color
    }

    background: Rectangle {
        implicitWidth: control.__config.background.width
        implicitHeight: control.__config.background.height
        readonly property bool lightScheme: Application.styleHints.colorScheme === Qt.Light
        readonly property color bakcgroundColorTint: control.down
                ? lightScheme ? Color.transparent("black", 0.02) : Color.transparent("white", 0.04)
                : control.hovered || control.highlighted
                ? lightScheme ? Color.transparent("black", 0.04) : Color.transparent("white", 0.06)
                : "transparent"
        color: Qt.tint(control.palette.window, bakcgroundColorTint)
    }
}
