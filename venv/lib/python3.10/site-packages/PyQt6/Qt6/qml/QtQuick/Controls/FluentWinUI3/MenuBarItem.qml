// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.FluentWinUI3.impl

T.MenuBarItem {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             implicitIndicatorHeight + topPadding + bottomPadding)

    spacing: __config.spacing || 0

    topPadding: __config.topPadding || 0
    bottomPadding: __config.bottomPadding || 0
    leftPadding: __config.leftPadding || 0
    rightPadding: __config.rightPadding || 0

    topInset: -__config.topInset || 0
    bottomInset: -__config.bottomInset || 0
    leftInset: -__config.leftInset || 0
    rightInset: -__config.rightInset || 0

    icon.width: __config.icon.width
    icon.height: __config.icon.height
    icon.color: Application.styleHints.accessibility.contrastPreference === Qt.HighContrast
                ? control.hovered || control.highlighted ? control.palette.highlight : control.palette.buttonText
                : !control.down
                ? control.palette.buttonText : Application.styleHints.colorScheme === Qt.Light
                ? Qt.rgba(control.palette.buttonText.r, control.palette.buttonText.g, control.palette.buttonText.b, 0.62)
                : Qt.rgba(control.palette.buttonText.r, control.palette.buttonText.g, control.palette.buttonText.b, 0.7725)

    readonly property string __currentState: [
        !control.enabled && "disabled",
        control.enabled && !control.down && (control.hovered || control.highlighted) && "hovered",
        down && "pressed"
    ].filter(Boolean).join("_") || "normal"
    readonly property var __config: Config.controls.toolbutton[__currentState] || {}

    readonly property Item __focusFrameTarget: control

    contentItem: IconLabel {
        spacing: control.spacing
        mirrored: control.mirrored
        display: control.display
        alignment: Qt.AlignLeft

        icon: control.icon
        text: control.text
        font: control.font
        color: control.icon.color
    }

    background: ButtonBackground {
        control: control
        implicitHeight: 30
        implicitWidth: 30
        radius: control.__config.background.topOffset
        subtle: (!control.checked || control.flat) && Application.styleHints.accessibility.contrastPreference !== Qt.HighContrast
        accented: control.checked
    }
}
