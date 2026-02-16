// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.FluentWinUI3.impl as Impl
import QtQuick.Templates as T
import QtQuick.Effects

T.ProgressBar {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    topPadding: __config.topPadding || 0
    bottomPadding: __config.bottomPadding || 0
    leftPadding: __config.leftPadding || 0
    rightPadding: __config.rightPadding || 0

    topInset: (__isHighContrast ? -1 : 0) - (__config.topInset || 0)
    bottomInset: (__isHighContrast ? -1 : 0) - (__config.bottomInset || 0)
    leftInset: (__isHighContrast ? -1 : 0) - (__config.leftInset || 0)
    rightInset: (__isHighContrast ? -1 : 0) - (__config.rightInset || 0)

    readonly property string __currentState: [
        !control.enabled && "disabled",
        control.indeterminate && "indeterminate"
    ].filter(Boolean).join("_") || "normal"
    readonly property var __config: Config.controls.progressbar[__currentState] || {}
    readonly property bool __isHighContrast: Application.styleHints.accessibility.contrastPreference === Qt.HighContrast

    contentItem: Item {
        implicitWidth: control.indeterminate ? parent.availableWidth : progress.implicitWidth
        implicitHeight: control.indeterminate ? control.__config.track.height : progress.implicitHeight
        scale: control.mirrored ? -1 : 1
        clip: control.indeterminate

        readonly property Rectangle progress: Rectangle {
            x: control.background.groove?.x - (control.__isHighContrast ? 0 : 1)
            y: control.background.groove?.y - (control.__isHighContrast ? 0 : 1)
            parent: control.contentItem
            visible: !control.indeterminate && control.value
            implicitWidth: control.__config.track.width
            implicitHeight: control.__config.track.height
            width: control.position * parent.width
            height: control.__config.track.height
            radius: control.__config.track.height * 0.5
            color: control.palette.accent
        }

        readonly property Rectangle animatedProgress: Rectangle {
            parent: control.contentItem
            implicitWidth: parent.width
            implicitHeight: control.__config.track.height
            radius: control.__config.track.height * 0.5
            clip: true
            visible: false
            color: "transparent"
            Rectangle {
                width: 0.5 * parent.width
                height: control.__config.track.height
                radius: control.__config.track.height * 0.5
                color: control.palette.accent
                SequentialAnimation on x {
                    loops: Animation.Infinite
                    running: control.indeterminate && control.visible
                    NumberAnimation {
                        from: -control.contentItem.animatedProgress.width
                        to: control.contentItem.width
                        easing.type: Easing.InOutCubic
                        duration: control.width * 8
                    }
                    NumberAnimation {
                        from: -control.contentItem.animatedProgress.width * 0.5
                        to: control.contentItem.width
                        easing.type: Easing.InOutCubic
                        duration: control.width * 5
                    }
                }
            }
        }

        readonly property Rectangle mask: Rectangle {
            parent: control.contentItem
            width: control.availableWidth
            height: control.contentItem.animatedProgress.height
            radius: control.contentItem.animatedProgress.radius
            visible: false
            color: control.palette.accent
            layer.enabled: true
            antialiasing: false
        }

        MultiEffect {
            visible: control.indeterminate
            source: control.contentItem.animatedProgress
            width: control.contentItem.animatedProgress.width
            height: control.contentItem.animatedProgress.height
            maskEnabled: true
            maskSource: control.contentItem.mask
        }
    }

    background: Rectangle {
        implicitWidth: groove.width
        radius: height * 0.5
        color: control.__isHighContrast ? control.palette.window : "transparent"
        border.color: control.__isHighContrast ? control.palette.text : "transparent"
        property Item groove: Impl.StyleImage {
            imageConfig: control.__config.groove
            visible: !control.indeterminate && !control.__isHighContrast
            parent: control.background
            height: implicitHeight
            width: parent.width
        }
    }
}
