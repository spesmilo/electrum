// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Fusion
import QtQuick.Controls.Fusion.impl

T.Dialog {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding,
                            implicitHeaderWidth,
                            implicitFooterWidth)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding
                             + (implicitHeaderHeight > 0 ? implicitHeaderHeight + spacing : 0)
                             + (implicitFooterHeight > 0 ? implicitFooterHeight + spacing : 0))

    padding: 6

    background: Rectangle {
        color: control.palette.window
        border.color: Fusion.highContrast ? control.palette.windowText : control.palette.mid
        radius: 2

        Rectangle {
            z: -1
            x: 1; y: 1
            width: parent.width - 2
            height: parent.height - 2
            color: control.palette.shadow
            opacity: 0.2
            radius: 2
        }
    }

    header: Label {
        text: control.title
        visible: control.title && parent?.parent === Overlay.overlay
        elide: Label.ElideRight
        font.bold: true
        padding: 6
        background: Rectangle {
            border.color: Fusion.highContrast ? control.palette.windowText : "transparent"
            color: "transparent"
            width: parent.width
            height: parent.height
            topLeftRadius: 2
            topRightRadius: 2
            Rectangle {
                x: 1; y: 1
                width: parent.width - 2
                height: parent.height - 2
                color: control.palette.window
                topLeftRadius: 2
                topRightRadius: 2
            }
        }
    }

    footer: DialogButtonBox {
        visible: count > 0
    }

    T.Overlay.modal: Rectangle {
        color: Fusion.topShadow
    }

    T.Overlay.modeless: Rectangle {
        color: Fusion.topShadow
    }
}
