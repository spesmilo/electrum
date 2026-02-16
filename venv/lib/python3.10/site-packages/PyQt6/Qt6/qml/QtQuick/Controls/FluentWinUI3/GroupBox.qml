// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.FluentWinUI3.impl as Impl
import QtQuick.Templates as T

T.GroupBox {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding,
                            implicitLabelWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    readonly property real __deltaY: (__config.background.y - __config.label.y) || 0
    readonly property real __deltaX: (__config.background.x - __config.label.x) || 0
    spacing: (__deltaY - __config.label.height) || 0

    topPadding: (__config.topPadding || 0) + (spacing >= 0 ? (label.height + spacing) : __deltaY)
    bottomPadding: __config.bottomPadding || 0
    leftPadding: (__config.leftPadding || 0) + (__deltaX >= 0 ? __deltaX : 0)
    rightPadding: __config.rightPadding || 0

    topInset: __deltaY > 0 ? __deltaY : 0
    bottomInset: -__config.bottomInset || 0
    leftInset: __deltaX > 0 ? __deltaX : 0
    rightInset: -__config.rightInset || 0

    readonly property string __currentState: [
        !control.enabled && "disabled",
        control.enabled && control.hovered && "hovered",
    ].filter(Boolean).join("_") || "normal"
    readonly property var __config: Config.controls.groupbox[__currentState] || {}

    label: T.Label {
        x: control.__deltaX > 0 ? 0 : -__deltaX
        y: control.__deltaY > 0 ? 0 : -__deltaY

        topPadding: control.__config.label_contentItem.topPadding || 0
        leftPadding: control.__config.label_contentItem.leftPadding || 0
        rightPadding: control.__config.label_contentItem.rightPadding || 0
        bottomPadding: control.__config.label_contentItem.bottomPadding || 0

        height: Math.max(implicitHeight, __config.label.height)

        text: control.title
        font: control.font
        color: control.palette.windowText
        elide: Text.ElideRight
        horizontalAlignment: control.__config.label_text.textHAlignment
        verticalAlignment: control.__config.label_text.textVAlignment

        background: Impl.StyleImage {
            imageConfig: control.__config.label_background
        }
    }

    background: Rectangle {
        color: "transparent"
        border.color: Application.styleHints.accessibility.contrastPreference === Qt.HighContrast ? control.palette.text : "transparent"
        radius: 4
        Impl.StyleImage {
            imageConfig: control.__config.background.filePath ? control.__config.background : Config.controls.frame["normal"].background // fallback to regular frame background
            width: parent.width
            height: parent.height
        }
    }
}
