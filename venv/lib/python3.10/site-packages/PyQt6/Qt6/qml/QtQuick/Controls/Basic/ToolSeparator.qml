// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Templates as T

T.ToolSeparator {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    padding: vertical ? 6 : 2
    verticalPadding: vertical ? 2 : 6

    contentItem: Rectangle {
        implicitWidth: control.vertical ? (Qt.styleHints.accessibility.contrastPreference === Qt.HighContrast ? 2 : 1) : 30
        implicitHeight: control.vertical ? 30 : (Qt.styleHints.accessibility.contrastPreference === Qt.HighContrast ? 2 : 1)
        color: control.palette.mid
    }
}
