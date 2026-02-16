// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.Universal

T.ToolSeparator {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    leftPadding: vertical ? 16 : 12
    rightPadding: vertical ? 15 : 12
    topPadding: vertical ? 12 : 16
    bottomPadding: vertical ? 12 : 15

    contentItem: Rectangle {
        implicitWidth: control.vertical ? 1 : 20
        implicitHeight: control.vertical ? 20 : 1
        color: control.Universal.baseMediumLowColor
    }
}
