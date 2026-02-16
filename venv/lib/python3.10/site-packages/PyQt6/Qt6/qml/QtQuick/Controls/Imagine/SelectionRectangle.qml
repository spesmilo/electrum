// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Imagine
import QtQuick.Controls.Imagine.impl

T.SelectionRectangle {
    id: control

    topLeftHandle: handle
    bottomRightHandle: handle

    Component {
        id: handle
        Image {
            id: image
            source: Imagine.url + "slider-handle"
            visible: SelectionRectangle.control.active
            ImageSelector on source {
                states: [
                    {"vertical": false},
                    {"horizontal": true},
                    {"disabled": false},
                    {"pressed": tapHandler.pressed || image.SelectionRectangle.dragging},
                    {"focused": true},
                    {"mirrored": false},
                    {"hovered": hoverHandler.hovered}
                ]
            }

            HoverHandler {
                id: hoverHandler
            }

            TapHandler  {
                id: tapHandler
            }
        }
    }
}
