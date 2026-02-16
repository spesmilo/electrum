// Copyright (C) 2018 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Fusion

T.SplitView {
    id: control
    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    handle: Rectangle {
        implicitWidth: control.orientation === Qt.Horizontal ? 2 : control.width
        implicitHeight: control.orientation === Qt.Horizontal ? control.height : 2
        color: {
            if (Fusion.highContrast)
                return T.SplitHandle.pressed ? Fusion.highlightedOutline(control.palette)
                                             : (enabled && T.SplitHandle.hovered ? control.palette.button : Fusion.outline(control.palette));
            else
                return T.SplitHandle.pressed ? control.palette.dark
                                             : (enabled && T.SplitHandle.hovered ? control.palette.midlight : control.palette.mid)
        }
    }
}
