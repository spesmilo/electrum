// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Fusion
import QtQuick.Controls.Fusion.impl

T.Drawer {
    id: control

    parent: T.Overlay.overlay

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    topPadding: SafeArea.margins.top + (control.edge === Qt.BottomEdge)
    leftPadding: SafeArea.margins.left + (control.edge === Qt.RightEdge)
    rightPadding: SafeArea.margins.right + (control.edge === Qt.LeftEdge)
    bottomPadding: SafeArea.margins.bottom + (control.edge === Qt.TopEdge)

    enter: Transition { SmoothedAnimation { velocity: 5 } }
    exit: Transition { SmoothedAnimation { velocity: 5 } }

    background: Rectangle {
        color: control.palette.window
        readonly property bool horizontal: control.edge === Qt.LeftEdge || control.edge === Qt.RightEdge
        Rectangle {
            width: parent.horizontal ? 1 : parent.width
            height: parent.horizontal ? parent.height : 1
            color: control.palette.mid
            x: control.edge === Qt.LeftEdge ? parent.width - 1 : 0
            y: control.edge === Qt.TopEdge ? parent.height - 1 : 0
        }
        Rectangle {
            width: parent.horizontal ? 1 : parent.width
            height: parent.horizontal ? parent.height : 1
            color: control.palette.shadow
            opacity: 0.2
            x: control.edge === Qt.LeftEdge ? parent.width : 0
            y: control.edge === Qt.TopEdge ? parent.height : 0
        }
    }

    T.Overlay.modal: Rectangle {
        color: Fusion.topShadow
    }

    T.Overlay.modeless: Rectangle {
        color: Fusion.topShadow
    }
}
