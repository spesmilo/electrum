// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Templates as T

Item {
    id: indicator

    required property T.AbstractButton control

    property Item handleBackground: Rectangle {
        parent: control.indicator
        implicitWidth: parent.width
        implicitHeight: parent.height
        radius: height * 0.5
        border.width: control.checked && Application.styleHints.accessibility.contrastPreference === Qt.NoPreference ? 0 : 1
        border.color: control.enabled ? Application.styleHints.accessibility.contrastPreference === Qt.HighContrast
                                      ? control.checked ? (control.hovered ? control.palette.text : "transparent") : (control.hovered ? control.palette.accent : control.palette.text)
                                      : Application.styleHints.colorScheme === Qt.Light ? "#9C000000" : "#9CFFFFFF"
                                      : Application.styleHints.colorScheme === Qt.Light ? "#37000000" : "#28FFFFFF"

        color: control.checked ? checkedColor : !control.enabled ? "#00FFFFFF"
                               : control.hovered ? Application.styleHints.colorScheme === Qt.Light ? "#0F000000" : "#0BFFFFFF"
                               : control.pressed ? Application.styleHints.colorScheme === Qt.Light ? "#18000000" : "#12FFFFFF"
                               : Application.styleHints.colorScheme === Qt.Light ? "#06000000" : "#19000000"

        readonly property color checkedColor: control.enabled ? (control.hovered
                                                              ? Application.styleHints.accessibility.contrastPreference === Qt.HighContrast
                                                              ? control.palette.window
                                                              : Qt.rgba(control.palette.accent.r, control.palette.accent.g, control.palette.accent.b, 0.9020)
                                                              : control.pressed ? Qt.rgba(control.palette.accent.r, control.palette.accent.g, control.palette.accent.b, 0.8)
                                                              : control.palette.accent)
                                                              : control.palette.accent

        property Item handle: Rectangle {
            parent: indicator.handleBackground
            x: Math.max(0, Math.min(parent.width - width, control.visualPosition * parent.width - (width / 2)))
            y: (parent.height - height) / 2
            width: control.pressed ? implicitWidth + 3 : implicitWidth
            implicitWidth: 20
            implicitHeight: 20
            radius: height / 2
            scale: control.hovered && control.enabled ? 0.8 : 0.7
            gradient: Gradient {
                GradientStop {
                    position: 0
                    color: !control.checked ? "transparent" : Application.styleHints.colorScheme === Qt.Light ? "#0F000000" : "#12FFFFFF"
                }
                GradientStop {
                    position: 0.5
                    color: !control.checked ? "transparent" : Application.styleHints.colorScheme === Qt.Light ? "#0F000000" : "#12FFFFFF"
                }
                GradientStop {
                    position: 0.95
                    color: !control.checked ? "transparent" : Application.styleHints.colorScheme === Qt.Light ? "#29000000" : "#18FFFFFF"
                }
            }

            Rectangle {
                x: (parent.width - width) / 2
                y: (parent.height - height) / 2
                width: parent.width - 2
                height: parent.height - 2
                radius: height / 2
                color: !control.checked ? Application.styleHints.accessibility.contrastPreference === Qt.HighContrast
                                        ? (control.hovered ? control.palette.accent : control.palette.text)
                                        : control.palette.placeholderText
                                        : Application.styleHints.accessibility.contrastPreference === Qt.HighContrast
                                        ? (control.hovered ? control.palette.text : control.palette.window)
                                        : Application.styleHints.colorScheme === Qt.Dark ? "black" : "white"
            }

            Behavior on scale {
                NumberAnimation{
                    duration: 167
                    easing.type: Easing.OutCubic
                }
            }
            Behavior on x  {
                enabled: !control.pressed
                NumberAnimation {
                    duration: 167
                    easing.type: Easing.OutCubic
                }
            }
        }
    }
}
