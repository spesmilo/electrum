// Copyright (C) 2025 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T

T.HeaderViewDelegate {
    id: control

    // same as AbstractButton.qml
    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    padding: 8

    highlighted: selected

    background: Rectangle {
        border.color: Qt.styleHints.accessibility.contrastPreference === Qt.HighContrast ?
                      control.palette.windowText : control.palette.midlight
        color: control.palette.light
    }

    contentItem: Label {
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        color: control.palette.windowText
        text: control.model[control.headerView.textRole]
    }
}
