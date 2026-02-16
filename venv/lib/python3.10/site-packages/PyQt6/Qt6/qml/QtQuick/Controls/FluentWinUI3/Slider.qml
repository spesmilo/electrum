// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.FluentWinUI3.impl as Impl
import QtQuick.Templates as T

T.Slider {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitHandleWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitHandleHeight + topPadding + bottomPadding)

    topPadding: horizontal ? __config.topPadding : __config.leftPadding || 0
    leftPadding: horizontal ? __config.leftPadding : __config.bottomPadding || 0
    rightPadding: horizontal ? __config.rightPadding : __config.topPadding || 0
    bottomPadding: horizontal ? __config.bottomPadding : __config.rightPadding || 0

    readonly property string __currentState: [
        !control.enabled && "disabled",
        control.enabled && !control.pressed && control.hovered && "hovered",
        control.pressed && "pressed"
    ].filter(Boolean).join("_") || "normal"
    readonly property var __config: Config.controls.slider[__currentState] || {}

    readonly property Item __focusFrameTarget: control

    readonly property real __steps: Math.abs(to - from) / stepSize
    readonly property bool __isDiscrete: stepSize >= Number.EPSILON
        && Math.abs(Math.round(__steps) - __steps) < Number.EPSILON

    readonly property bool __isHighContrast: Application.styleHints.accessibility.contrastPreference === Qt.HighContrast

    handle: ItemGroup {
        x: Math.round(control.leftPadding + (control.horizontal
            ? control.visualPosition * (control.availableWidth - width)
            : (control.availableWidth - width) / 2))
        y: Math.round(control.topPadding + (control.horizontal
            ? (control.availableHeight - height) / 2
            : control.visualPosition * (control.availableHeight - height)))

        Impl.StyleImage {
            visible: !control.__isHighContrast
            imageConfig: control.__config.handle
        }

        Rectangle {
            visible: control.__isHighContrast
            implicitWidth: control.__config.handle.width
            implicitHeight: control.__config.handle.height
            color: control.palette.buttonText
            radius: width / 2
        }

        property HoverHandler _hoverHandler: HoverHandler {
            parent: control.handle
            target: control.handle
        }

        property Rectangle indicator: Rectangle {
            property real diameter: !control.enabled ? 10
                                                     : control.pressed ? 8
                                                     : control.__isHighContrast && !control.hovered ? 0
                                                     : control.handle?._hoverHandler.hovered ? 14 : 10
            parent: control.handle
            width: diameter
            height: diameter
            radius: diameter * 0.5
            x: (control.__config.handle.width - width) / 2
            y: (control.__config.handle.height - height) / 2

            color: control.enabled ? (control.hovered ? Qt.rgba(control.palette.accent.r, control.palette.accent.g, control.palette.accent.b, 0.9020)
                                   : control.pressed ? Qt.rgba(control.palette.accent.r, control.palette.accent.g, control.palette.accent.b, 0.8)
                                   : control.palette.accent)
                                   : control.palette.accent
            Behavior on diameter {
                // From WindowsUI 3 Animation Values
                NumberAnimation {
                    duration: 167
                    easing.type: Easing.OutCubic
                }
            }
        }
    }

    background: Item {
        implicitWidth: control.horizontal
            ? (control.__config.groove.width)
            : (control.__config.groove.height)
        implicitHeight: control.horizontal
            ? (control.__config.groove.height)
            : (control.__config.groove.width)

        property Item _background: Impl.StyleImage {
            visible: !control.__isHighContrast
            parent: control.background
            width: parent.width
            height: parent.height
            imageConfig: control.__config.background

            property Item groove: Impl.StyleImage {
                parent: control.background._background
                x: control.leftPadding - control.leftInset + (control.horizontal
                    ? control.__config.handle.width / 2
                    : (control.availableWidth - width) / 2)
                y: control.topPadding - control.topInset + (control.horizontal
                    ? ((control.availableHeight - height) / 2)
                    : control.__config.handle.height / 2)

                width: control.horizontal
                    ? control.availableWidth - control.__config.handle.width
                    : implicitWidth
                height: control.horizontal
                    ? implicitHeight
                    : control.availableHeight - control.__config.handle.width
                imageConfig: control.__config.groove
                horizontal: control.horizontal

                property Rectangle track: Rectangle {
                    parent: control.background._background.groove
                    y: control.horizontal ? 0 : parent.height - (parent.height * control.position)
                    implicitWidth: control.horizontal ? control.__config.track.width : control.__config.track.height
                    implicitHeight: control.horizontal ? control.__config.track.height : control.__config.track.width
                    width: control.horizontal ? parent.width * control.position : parent.width
                    height: control.horizontal ? parent.height : parent.height * control.position
                    radius: control.__config.track.height * 0.5
                    color: control.palette.accent
                }
            }

            property Repeater ticksTop: Repeater {
                parent: control.__isHighContrast ? control.background._highContrastBackground : control.background._background.groove
                model: control.__isDiscrete ? Math.floor(control.__steps) + 1 : 0
                delegate: Rectangle {
                    width: control.horizontal ? 1 : 4
                    height: control.horizontal ? 4 : 1
                    x: control.horizontal
                        ? 6 + index * (parent.width - 2 * 6 - width) / (control.background._background.ticksTop.model - 1)
                        : -4 - width
                    y: control.horizontal
                        ? -4 - height
                        : 6 + index * (parent.height - 2 * 6 - height) / (control.background._background.ticksTop.model - 1)
                    color: Application.styleHints.colorScheme == Qt.Light ? "#9C000000" : "#9AFFFFFF"

                    required property int index
                }
            }

            property Repeater ticksBottom: Repeater {
                parent: control.__isHighContrast ? control.background._highContrastBackground : control.background._background.groove
                model: control.__isDiscrete ? Math.floor(control.__steps) + 1 : 0
                delegate: Rectangle {
                    width: control.horizontal ? 1 : 4
                    height: control.horizontal ? 4 : 1
                    x: control.horizontal
                        ? 6 + index * (parent.width - 2 * 6 - width) / (control.background._background.ticksBottom.model - 1)
                        : parent.width + 4
                    y: control.horizontal
                        ? parent.height + 4
                        : 6 + index * (parent.height - 2 * 6 - height) / (control.background._background.ticksBottom.model - 1)
                    color: Application.styleHints.colorScheme == Qt.Light ? "#9C000000" : "#9AFFFFFF"

                    required property int index
                }
            }
        }
        property Item _highContrastBackground: Rectangle {
            parent: control.background
            visible: control.__isHighContrast
            implicitWidth: control.horizontal ? 200 : 4
            implicitHeight: control.horizontal ? 4 : 200
            x: control.leftPadding - control.leftInset + (control.horizontal
                ? control.__config.handle.width / 2
                : (control.availableWidth - width) / 2)
            y: control.topPadding - control.topInset + (control.horizontal
                ? ((control.availableHeight - height) / 2)
                : control.__config.handle.height / 2)
            width: control.horizontal
                ? control.availableWidth - control.__config.handle.width
                : implicitWidth
            height: control.horizontal
                ? implicitHeight
                : control.availableHeight - control.__config.handle.width
            radius: 2
            color: control.palette.buttonText
            scale: control.horizontal && control.mirrored ? -1 : 1

            Rectangle {
                y: control.horizontal ? 0 : parent.height - (parent.height * control.position)
                implicitWidth: control.horizontal ? parent.width * control.position : parent.width
                implicitHeight: control.horizontal ? parent.height : parent.height * control.position
                radius: 2
                color: control.palette.highlight
            }
        }
    }
}
