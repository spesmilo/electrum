// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.FluentWinUI3.impl as Impl
import QtQuick.Templates as T

T.SpinBox {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            contentItem.implicitWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             up.implicitIndicatorHeight, down.implicitIndicatorHeight)

    property string __controlState: [
        enabled && (down.hovered || down.pressed) && "down",
        enabled && (up.hovered || up.pressed) && !(down.hovered || down.pressed) && "up",
        enabled && (hovered || down.hovered || up.hovered) && !(down.pressed || up.pressed) && "hovered",
        enabled && (down.pressed || up.pressed) && "pressed",
        !enabled && "disabled"
    ].filter(Boolean).join("_") || "normal"
    readonly property var __config: Config.controls.spinbox[__controlState] || {}
    readonly property var __downConfig: value == from ? Config.controls.spinbox["atlimit"] : __config
    readonly property var __upConfig: value == to ? Config.controls.spinbox["atlimit"] : __config

    spacing: __config.contentItem.spacing || 0
    leftPadding: ((!mirrored ? __config.leftPadding : __config.rightPadding) || 0) + (mirrored ? (up.indicator ? up.indicator.width * 2 : 0) : 0)
    rightPadding: ((!mirrored ? __config.rightPadding : __config.leftPadding) || 0) + (!mirrored ? (up.indicator ? up.indicator.width * 2 : 0) : 0)
    topPadding: __config.topPadding || 0
    bottomPadding: __config?.bottomPadding || 0

    topInset: -__config.topInset || 0
    bottomInset: -__config.bottomInset || 0
    leftInset: -__config.leftInset || 0
    rightInset: -__config.rightInset || 0

    validator: IntValidator {
        locale: control.locale.name
        bottom: Math.min(control.from, control.to)
        top: Math.max(control.from, control.to)
    }

    contentItem: TextInput {
        clip: width < implicitWidth
        text: control.displayText
        opacity: control.enabled ? 1 : 0.3

        font: control.font
        color: control.palette.text
        selectionColor: control.palette.highlight
        selectedTextColor: control.palette.highlightedText
        horizontalAlignment: control.mirrored ? Text.AlignRight : Text.AlignLeft
        verticalAlignment: Text.AlignVCenter

        readOnly: !control.editable
        validator: control.validator
        inputMethodHints: control.inputMethodHints
    }

    down.indicator: Impl.StyleImage {
        x: !control.mirrored ? control.up.indicator ? (control.up.indicator.x - width) : 0
                             : control.__config.rightPadding
        y: control.topPadding
        height: control.availableHeight
        imageConfig: control.__downConfig.indicator_down_background

        Impl.StyleImage {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            imageConfig: control.__downConfig.indicator_down_icon
        }
    }

    up.indicator: Impl.StyleImage {
        x: control.mirrored ? control.__config.rightPadding + (control.down.indicator ? control.down.indicator.width : 0)
                            : control.width - width - control.__config.rightPadding
        y: control.topPadding
        height: control.availableHeight
        imageConfig: control.__upConfig.indicator_up_background

        Impl.StyleImage {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            imageConfig: control.__upConfig.indicator_up_icon
        }
    }

    background: Impl.StyleImage {
        imageConfig: control.__config.background
        Item {
            visible: control.activeFocus
            width: parent.width
            height: 2
            y: parent.height - height
            Impl.FocusStroke {
                width: parent.width
                height: parent.height
                radius: control.__config.background.bottomOffset
                color: control.palette.accent
            }
        }
    }
}
