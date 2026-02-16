// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Universal

T.SelectionRectangle {
    id: control

    topLeftHandle: handle
    bottomRightHandle: handle

    Component {
        id: handle
        Rectangle {
            implicitWidth: 8
            implicitHeight: 24
            radius: 4
            color: tapHandler.pressed || SelectionRectangle.dragging ? control.Universal.chromeHighColor :
                   hoverHandler.hovered ? control.Universal.chromeAltLowColor :
                   control.Universal.accent
            visible: control.active

            property Item control: SelectionRectangle.control

            HoverHandler {
                id: hoverHandler
            }

            TapHandler  {
                id: tapHandler
            }
        }
    }
}
