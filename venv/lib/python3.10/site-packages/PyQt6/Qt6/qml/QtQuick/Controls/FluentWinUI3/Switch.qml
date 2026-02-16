// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.FluentWinUI3.impl

T.Switch {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding,
                            implicitIndicatorWidth)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             implicitIndicatorHeight + topPadding + bottomPadding)

    spacing: __config.spacing || 0

    topPadding: control.text ? __config.topPadding || 0 : 0
    leftPadding: control.text ? __config.leftPadding || 0 : 0
    rightPadding: control.text ? __config.rightPadding || 0 : 0
    bottomPadding: control.text ? __config.bottomPadding || 0 : 0

    topInset: -__config.topInset || 0
    bottomInset: -__config.bottomInset || 0
    leftInset: -__config.leftInset || 0
    rightInset: -__config.rightInset || 0

    readonly property string __currentState: [
        control.checked && "checked",
        !control.enabled && "disabled",
        control.enabled && !control.down && control.hovered && "hovered",
        control.down && "pressed"
    ].filter(Boolean).join("_") || "normal"
    readonly property var __config: Config.controls.switch_[__currentState] || {}
    readonly property bool __mirroredIndicator: control.mirrored !== (__config.mirrored || false)

    readonly property Item __focusFrameTarget: control

    indicator: SwitchIndicator {
        x: control.text ? (control.__mirroredIndicator ? control.width - width - control.rightPadding : control.leftPadding) : control.leftPadding + (control.availableWidth - width) / 2
        y: control.topPadding + (control.availableHeight - height) / 2
        implicitWidth: control.__config.handle_background.width
        implicitHeight: control.__config.handle_background.height
        control: control
    }

    contentItem: Text {
        leftPadding: control.indicator && !control.__mirroredIndicator ? control.indicator.width + control.spacing : 0
        rightPadding: control.indicator && control.__mirroredIndicator ? control.indicator.width + control.spacing : 0

        text: control.text
        font: control.font
        color: control.palette.text
        elide: Text.ElideRight
        horizontalAlignment: Text.AlignLeft
        verticalAlignment: Text.AlignVCenter
    }
}
