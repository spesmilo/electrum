// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.Universal

Item {
    id: indicator
    implicitWidth: 44
    implicitHeight: 20

    property T.AbstractButton control

    Rectangle {
        width: parent.width
        height: parent.height

        radius: 10
        color: !indicator.control.enabled ? "transparent" :
                indicator.control.pressed ? indicator.control.Universal.baseMediumColor :
                indicator.control.checked ? indicator.control.Universal.accent : "transparent"
        border.color: !indicator.control.enabled ? indicator.control.Universal.baseLowColor :
                       indicator.control.checked && !indicator.control.pressed ? indicator.control.Universal.accent :
                       indicator.control.hovered && !indicator.control.checked && !indicator.control.pressed ? indicator.control.Universal.baseHighColor : indicator.control.Universal.baseMediumColor
        opacity: enabled && indicator.control.hovered && indicator.control.checked && !indicator.control.pressed ? (indicator.control.Universal.theme === Universal.Light ? 0.7 : 0.9) : 1.0
        border.width: 2
    }

    Rectangle {
        width: 10
        height: 10
        radius: 5

        color: !indicator.control.enabled ? indicator.control.Universal.baseLowColor :
                indicator.control.pressed || indicator.control.checked ? indicator.control.Universal.chromeWhiteColor :
                indicator.control.hovered && !indicator.control.checked ? indicator.control.Universal.baseHighColor : indicator.control.Universal.baseMediumHighColor

        x: Math.max(5, Math.min(parent.width - width - 5,
                                indicator.control.visualPosition * parent.width - (width / 2)))
        y: (parent.height - height) / 2

        Behavior on x {
            enabled: !indicator.control.pressed
            SmoothedAnimation { velocity: 200 }
        }
    }
}
