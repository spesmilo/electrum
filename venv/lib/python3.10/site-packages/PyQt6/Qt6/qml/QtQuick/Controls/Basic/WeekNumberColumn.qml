// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T

T.AbstractWeekNumberColumn {
    id: control

    implicitWidth: Math.max(background ? background.implicitWidth : 0,
                            contentItem.implicitWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(background ? background.implicitHeight : 0,
                             contentItem.implicitHeight + topPadding + bottomPadding)

    spacing: 6
    leftPadding: 6
    rightPadding: 6
    font.bold: true

    //! [delegate]
    delegate: Text {
        text: weekNumber
        font: control.font
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter

        required property int weekNumber
    }
    //! [delegate]

    //! [contentItem]
    contentItem: Column {
        spacing: control.spacing
        Repeater {
            model: control.source
            delegate: control.delegate
        }
    }
    //! [contentItem]
}
