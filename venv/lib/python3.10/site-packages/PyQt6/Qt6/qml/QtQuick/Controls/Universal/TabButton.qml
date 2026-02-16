// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Universal

T.TabButton {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    padding: 12 // PivotItemMargin
    spacing: 8

    icon.width: 20
    icon.height: 20
    icon.color: Color.transparent(control.hovered ? control.Universal.baseMediumHighColor : control.Universal.foreground,
                                                    control.checked || control.down || control.hovered ? 1.0 : 0.2)

    contentItem: IconLabel {
        spacing: control.spacing
        mirrored: control.mirrored
        display: control.display

        icon: control.icon
        text: control.text
        font: control.font
        color: Color.transparent(enabled && control.hovered ? control.Universal.baseMediumHighColor : control.Universal.foreground,
                                 control.checked || control.down || (enabled && control.hovered) ? 1.0 : 0.2)
    }
}
