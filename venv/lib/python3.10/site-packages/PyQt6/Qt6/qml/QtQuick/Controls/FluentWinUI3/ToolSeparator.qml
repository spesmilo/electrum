// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T

T.ToolSeparator {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    padding: 2
    topPadding: vertical ? __config.topPadding : padding
    bottomPadding: vertical ? __config.bottomPadding : padding
    leftPadding: vertical ? padding : __config.topPadding
    rightPadding: vertical ? padding : __config.bottomPadding

    readonly property var __config: Config.controls.toolbutton["normal"] || {}

    contentItem: Rectangle {
        implicitWidth: control.vertical ? 1 : control.__config.background.height
        implicitHeight: control.vertical ? control.__config.background.height : 1
        color: Application.styleHints.colorScheme === Qt.Light ? "#0F000000" : "#15FFFFFF"
    }
}
