// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.FluentWinUI3.impl as Impl
import QtQuick.Effects

T.Menu {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    leftPadding: 5
    topPadding: 5
    rightPadding: 5
    bottomPadding: 5
    margins: 0
    overlap: 4

    readonly property var __config: Config.controls.popup["normal"]
    readonly property bool __isHighContrast: Application.styleHints.accessibility.contrastPreference === Qt.HighContrast

    leftInset: -__config.background.leftShadow
    topInset: -__config.background.topShadow
    rightInset: -__config.background.rightShadow
    bottomInset: -__config.background.bottomShadow

    delegate: MenuItem { }

    contentItem: ListView {
        implicitHeight: contentHeight
        model: control.contentModel
        interactive: Window.window
                     ? contentHeight + control.topPadding + control.bottomPadding > control.height
                     : false
        currentIndex: control.currentIndex
        spacing: 4
        clip: true

        ScrollIndicator.vertical: ScrollIndicator {}
    }

    property real __heightScale: 1
    height: __heightScale * implicitHeight
    enter: Transition {
        NumberAnimation { property: "__heightScale"; from: 0.33; to: 1; easing.type: Easing.OutCubic; duration: 250 }
    }

    background: Impl.StyleImage {
        implicitWidth: 200 + imageConfig.leftShadow + imageConfig.rightShadow
        implicitHeight: 30 + imageConfig.topShadow + imageConfig.bottomShadow
        imageConfig: control.__config.background
        drawShadowWithinBounds: true
        Rectangle {
            x: -control.leftInset
            y: -control.topInset
            implicitWidth: parent.width + control.leftInset + control.rightInset
            implicitHeight: parent.height + control.topInset + control.bottomInset
            visible: control.__isHighContrast
            radius: 8
            color: control.palette.window
            border.color: control.palette.text
            border.width: 2
        }
    }

    T.Overlay.modal: Rectangle {
        color: "transparent"
    }

    T.Overlay.modeless: Rectangle {
        color: "transparent"
    }
}
