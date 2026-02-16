// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.Basic.impl
import QtQuick.Templates as T

T.Dial {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    background: DialImpl {
        implicitWidth: 184
        implicitHeight: 184
        color: control.visualFocus ? control.palette.highlight : control.palette.dark
        progress: control.position
        opacity: control.enabled ? 1 : 0.3
        startAngle: control.startAngle
        endAngle: control.endAngle
    }

    handle: ColorImage {
        x: control.background.x + control.background.width / 2 - width / 2
        y: control.background.y + control.background.height / 2 - height / 2
        width: 14
        height: 10
        defaultColor: "#353637"
        color: control.visualFocus ? control.palette.highlight : control.palette.dark
        source: "qrc:/qt-project.org/imports/QtQuick/Controls/Basic/images/dial-indicator.png"
        antialiasing: true
        opacity: control.enabled ? 1 : 0.3
        transform: [
            Translate {
                y: -Math.min(control.background.width, control.background.height) * 0.4
                   + (control.handle ? control.handle.height / 2 : 0)
            },
            Rotation {
                angle: control.angle
                origin.x: control.handle ? control.handle.width / 2 : 0
                origin.y: control.handle ? control.handle.height / 2 : 0
            }
        ]
    }
}
