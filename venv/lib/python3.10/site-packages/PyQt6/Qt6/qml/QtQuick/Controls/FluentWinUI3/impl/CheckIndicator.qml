// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Templates as T
import QtQuick.Shapes

ColorImage {
    id: indicator

    required property T.AbstractButton control
    required property url filePath

    readonly property color __color: {
        if (Application.styleHints.accessibility.contrastPreference === Qt.HighContrast)
            return control.palette.button
        if (control.enabled && control.checkState !== Qt.Unchecked)
            return control.palette.accent
        return defaultColor
    }

    readonly property color __indicatorColor: {
        if (Application.styleHints.accessibility.contrastPreference === Qt.HighContrast) {
            if (control.checkState === Qt.Checked)
                return control.down ? control.palette.buttonText : control.hovered ? control.palette.button : control.palette.highlightedText
            if (control.checkState === Qt.PartiallyChecked)
                return control.hovered && !control.down ? control.palette.highlight : control.palette.highlightedText
            return "transparent"
        } else if (control.down) {
            return Application.styleHints.colorScheme === Qt.Light ? Qt.rgba(1, 1, 1, 0.7) : Qt.rgba(0, 0, 0, 0.5)
        } else if (Application.styleHints.colorScheme === Qt.Dark && !control.enabled)
            return Qt.rgba(1, 1, 1, 0.5302)
        else if (Application.styleHints.colorScheme === Qt.Dark)
            return "black"
        else
            return "white"
    }

    source: filePath
    color: __color

    Rectangle {
        anchors.fill: parent
        radius: 4
        color: {
            if (Application.styleHints.accessibility.contrastPreference === Qt.HighContrast) {
                if (control.checkState === Qt.Unchecked)
                    return control.down ? control.palette.highlight : control.hovered ? control.palette.highlightedText : control.palette.button
                if (control.checkState === Qt.PartiallyChecked)
                    return control.hovered && !control.down ? control.palette.highlightedText : control.palette.highlight
                return control.down ? control.palette.button : control.hovered ? control.palette.buttonText : control.palette.highlight
            }
            return "transparent"
        }
        border.color: {
            if (Application.styleHints.accessibility.contrastPreference === Qt.HighContrast) {
                if (control.checkState === Qt.Unchecked)
                    return control.hovered ? control.palette.highlight : control.palette.buttonText
                if (control.checkState === Qt.PartiallyChecked)
                    return control.palette.highlight
            }
            return "transparent"
        }

        // TODO: Add animation for checkmark indicator
        Shape {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            width: 12
            height: 12
            visible: control.checked

            antialiasing: true
            preferredRendererType: Shape.CurveRenderer

            ShapePath {
                strokeWidth: 1
                strokeColor: indicator.__indicatorColor
                fillColor: "transparent"
                capStyle: ShapePath.RoundCap
                joinStyle: ShapePath.RoundJoin

                startX: 1
                startY: 6
                PathLine { x: 5; y: 10 }
                PathLine { x: 11; y: 3 }
            }
        }

        Rectangle {
            visible: control.checkState === Qt.PartiallyChecked
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            width: 8
            height: 1
            radius: height * 0.5
            color: indicator.__indicatorColor
        }
    }
}
