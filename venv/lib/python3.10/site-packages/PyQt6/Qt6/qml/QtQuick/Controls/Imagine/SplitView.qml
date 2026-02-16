// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.Imagine
import QtQuick.Controls.Imagine.impl

T.SplitView {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    handle: NinePatchImage {
        source: Imagine.url + "splitview-handle"
        NinePatchImageSelector on source {
            states: [
                {"vertical": control.orientation === Qt.Vertical},
                {"horizontal":control.orientation === Qt.Horizontal},
                {"disabled": !control.enabled},
                {"pressed": T.SplitHandle.pressed},
                {"mirrored": control.mirrored},
                {"hovered": T.SplitHandle.hovered}
            ]
        }
    }
}
