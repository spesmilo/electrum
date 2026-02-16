// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Templates as T

ColorImage {
    id: indicator

    required property T.AbstractButton control
    required property url filePath

    source: filePath
    color: control.enabled && control.checked ? control.palette.accent : defaultColor

    Rectangle {
        anchors.fill: parent
        visible: Application.styleHints.accessibility.contrastPreference === Qt.HighContrast
        color: {
            if (control.hovered)
                return control.checked ? control.palette.button : control.palette.highlightedText
            return control.checked ? control.palette.highlightedText : control.palette.button
        }
        border.width: control.down ? 0 : 1
        border.color: {
            if (control.hovered)
                return control.checked ? control.palette.buttonText : control.palette.highlight
            return control.checked ? control.palette.highlight : control.palette.buttonText
        }
        radius: height * 0.5
    }

    property Item indicatorBackground: Rectangle {
        parent: control.indicator
        x: (parent.width - width) / 2
        y: (parent.height - height) / 2
        width: Application.styleHints.accessibility.contrastPreference === Qt.HighContrast ? 15 : 10
        height: Application.styleHints.accessibility.contrastPreference === Qt.HighContrast ? 15 : 10
        radius: height * 0.5
        scale: !control.checked && !control.down ? 0 : control.down && control.checked ? 0.8 : control.hovered ? 1.2 : 1

        gradient: Gradient {
            GradientStop {
                position: 0
                color: !control.checked ? "transparent" : Application.styleHints.colorScheme == Qt.Light ? "#0F000000" : "#12FFFFFF"
            }
            GradientStop {
                position: 0.5
                color: !control.checked ? "transparent" : Application.styleHints.colorScheme == Qt.Light ? "#0F000000" : "#12FFFFFF"
            }
            GradientStop {
                position: 0.95
                color: !control.checked ? "transparent" : Application.styleHints.colorScheme == Qt.Light ? "#29000000" : "#18FFFFFF"
            }
        }

        Rectangle {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            width: parent.width - 2
            height: parent.height - 2
            radius: height * 0.5
            color: {
                if (Application.styleHints.accessibility.contrastPreference === Qt.HighContrast) {
                    if (control.checked && (control.down || control.hovered))
                        return control.palette.buttonText
                    return control.palette.highlight
                } else
                    return Application.styleHints.colorScheme === Qt.Dark ? "black" : "white"
            }
        }

        Behavior on scale {
            NumberAnimation {
                duration: 167
                easing.type: Easing.OutCubic
            }
        }
    }
}
