// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.Imagine
import QtQuick.Controls.Imagine.impl

T.ToolBar {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    topPadding: SafeArea.margins.top + (background ? background.topPadding : 0)
    leftPadding: SafeArea.margins.left + (background ? background.leftPadding : 0)
    rightPadding: SafeArea.margins.right + (background ? background.rightPadding : 0)
    bottomPadding: SafeArea.margins.bottom + (background ? background.bottomPadding : 0)

    topInset: background ? -background.topInset || 0 : 0
    leftInset: background ? -background.leftInset || 0 : 0
    rightInset: background ? -background.rightInset || 0 : 0
    bottomInset: background ? -background.bottomInset || 0 : 0

    background: NinePatchImage {
        source: Imagine.url + "toolbar-background"
        NinePatchImageSelector on source {
            states: [
                {"disabled": !control.enabled},
                {"header": control.position === T.ToolBar.Header },
                {"footer": control.position === T.ToolBar.Footer },
                {"mirrored": control.mirrored}
            ]
        }
    }
}
