// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Templates as T

Rectangle {
    id: buttonBackground

    visible: (control.enabled && control.hovered) || control.down || accented || !subtle

    required property T.AbstractButton control
    property bool subtle: false
    property bool accented: control.highlighted || control.checked

    readonly property bool lightScheme: Application.styleHints.colorScheme === Qt.Light
    readonly property bool highContrastScheme: Application.styleHints.accessibility.contrastPreference === Qt.HighContrast

    readonly property bool hasGradientStroke: !hasSolidStroke && !subtle && control.enabled
    readonly property bool hasSolidStroke: highContrastScheme
        || (!subtle && (control.down || (!control.enabled && !accented)
        || (!lightScheme && !accented)))
    readonly property color defaultStrokeColor: highContrastScheme
        ? (control.enabled && (control.hovered || buttonBackground.accented)) ? control.palette.highlight : control.palette.buttonText
        : accented ? Qt.tint(control.palette.accent, control.palette.light)
        : control.palette.midlight
    readonly property color secondaryStrokeColor: accented ? Qt.tint(control.palette.accent, control.palette.mid) : control.palette.dark
    readonly property color backgroundColor: {
        if (highContrastScheme) {
            if (subtle)
                return control.palette.highlight
            if (accented) {
                if (control.enabled && control.hovered && !control.down)
                    return control.palette.buttonText
                if (control.enabled && !control.down)
                    return control.palette.highlight
            } else if (control.enabled && (control.hovered || control.down)) {
                return (control as T.MenuBarItem) ? control.palette.button : control.palette.highlightedText
            }
            return control.palette.button
        }
        if (accented) {
            if (control.enabled && control.down) {
                if (lightScheme)
                    return Qt.tint(control.palette.accent, Color.transparent("white", 0.2))
                return Qt.tint(control.palette.accent, Color.transparent("black", 0.2))
            }
            if (control.enabled && control.hovered) {
                if (lightScheme)
                    return Qt.tint(control.palette.accent, Color.transparent("white", 0.1))
                return Qt.tint(control.palette.accent, Color.transparent("black", 0.1))
            }
            return control.palette.accent
        }

        if (subtle) {
            if (control.down)
                return lightScheme ? Color.transparent("black", 0.02) : Color.transparent("white", 0.04)
            if (control.hovered)
                return lightScheme ? Color.transparent("black", 0.04) : Color.transparent("white", 0.06)
        }

        if (control.down) {
            if (lightScheme)
                return Qt.rgba(control.palette.button.r * 0.97, control.palette.button.g * 0.97, control.palette.button.b * 0.97, 0.3)
            return Color.transparent(control.palette.button, 0.03)
        } else if (control.enabled && control.hovered) {
            if (lightScheme)
                return Qt.rgba(control.palette.button.r * 0.97, control.palette.button.g * 0.97, control.palette.button.b * 0.97, 0.5)
            return Color.transparent(control.palette.button, 0.08)
        } else {
            return control.palette.button
        }
    }

    gradient: Gradient {
        GradientStop {
            position: 0
            color: hasGradientStroke ? defaultStrokeColor : "transparent"
        }
        GradientStop {
            position: 0.91
            color: hasGradientStroke ? defaultStrokeColor : "transparent"
        }
        GradientStop {
            position: 1.0
            color: hasGradientStroke ? secondaryStrokeColor : "transparent"
        }
    }

    Rectangle {
        x: !buttonBackground.hasGradientStroke ? 0 : border.width
        y: !buttonBackground.hasGradientStroke ? 0 : border.width
        width: !buttonBackground.hasGradientStroke ? parent.width : parent.width - border.width * 2
        height: !buttonBackground.hasGradientStroke ? parent.height : parent.height - border.width * 2
        radius: !buttonBackground.hasGradientStroke ? buttonBackground.radius : buttonBackground.radius - border.width
        border.width: 1
        border.color: buttonBackground.hasGradientStroke || buttonBackground.subtle
            || (highContrastScheme && !buttonBackground.accented && control.down && !(control as T.MenuBarItem))
            || (!highContrastScheme && buttonBackground.accented && (!control.enabled || control.down))
            ? "transparent" : buttonBackground.defaultStrokeColor
        color: buttonBackground.backgroundColor
    }
}
