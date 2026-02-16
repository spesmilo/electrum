// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.Universal

Rectangle {
    id: indicator
    implicitWidth: 20
    implicitHeight: 20
    radius: width / 2
    color: "transparent"
    border.width: 2 // RadioButtonBorderThemeThickness
    border.color:  control.checked ? "transparent" :
                  !control.enabled ? control.Universal.baseLowColor :
                   control.down ? control.Universal.baseMediumColor :
                   control.hovered ? control.Universal.baseHighColor : control.Universal.baseMediumHighColor

    property var control

    Rectangle {
        id: checkOuterEllipse
        width: parent.width
        height: parent.height

        radius: width / 2
        opacity: indicator.control.checked ? 1 : 0
        color: "transparent"
        border.width: 2 // RadioButtonBorderThemeThickness
        border.color: !indicator.control.enabled ? indicator.control.Universal.baseLowColor :
                       indicator.control.down ? indicator.control.Universal.baseMediumColor : indicator.control.Universal.accent
    }

    Rectangle {
        id: checkGlyph
        x: (parent.width - width) / 2
        y: (parent.height - height) / 2
        width: parent.width / 2
        height: parent.height / 2

        radius: width / 2
        opacity: indicator.control.checked ? 1 : 0
        color: !indicator.control.enabled ? indicator.control.Universal.baseLowColor :
                indicator.control.down ? indicator.control.Universal.baseMediumColor :
                indicator.control.hovered ? indicator.control.Universal.baseHighColor : indicator.control.Universal.baseMediumHighColor
    }
}
