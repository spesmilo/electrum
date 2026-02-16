// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.FluentWinUI3.impl as Impl
import QtQuick.Templates as T

T.Popup {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    topPadding: __config.topPadding || 0
    bottomPadding: __config.bottomPadding || 0
    leftPadding: __config.leftPadding || 0
    rightPadding: __config.rightPadding || 0

    topInset: -__config.topInset || 0
    bottomInset: -__config.bottomInset || 0
    leftInset: -__config.leftInset || 0
    rightInset: -__config.rightInset || 0

    readonly property string __currentState: "normal"
    readonly property var __config: Config.controls.popup[__currentState] || {}
    readonly property bool __isHighContrast: Application.styleHints.accessibility.contrastPreference === Qt.HighContrast

    enter: Transition {
        NumberAnimation { property: "opacity"; from: 0.0; to: 1.0; easing.type: Easing.Linear; duration: 83 }
        NumberAnimation { property: "scale"; from: control.modal ? 1.05 : 1; to: 1; easing.type: Easing.OutCubic; duration: 167 }
    }

    exit: Transition {
        NumberAnimation { property: "opacity"; from: 1.0; to: 0.0; easing.type: Easing.Linear; duration: 83 }
        NumberAnimation { property: "scale"; from: 1; to: control.modal ? 1.05 : 1; easing.type: Easing.OutCubic; duration: 167 }
    }

    background: Impl.StyleImage {
        implicitWidth: 320
        implicitHeight: 72
        imageConfig: control.__config.background
        drawShadowWithinBounds: control.__isHighContrast
        Rectangle {
            implicitWidth: parent.width
            implicitHeight: parent.height
            visible: control.__isHighContrast
            radius: 4
            color: control.palette.window
            border.color: control.palette.text
            border.width: 2
        }
    }

    T.Overlay.modal: Rectangle {
        color: Color.transparent(control.palette.shadow, 0.3)
    }

    T.Overlay.modeless: Rectangle {
        color: "transparent"
    }
}
