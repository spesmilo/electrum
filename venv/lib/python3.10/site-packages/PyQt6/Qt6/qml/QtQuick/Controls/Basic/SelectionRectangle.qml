// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Shapes
import QtQuick.Templates as T

T.SelectionRectangle {
    id: control

    topLeftHandle: Handle {}
    bottomRightHandle: Handle {}

    component Handle : Rectangle {
        id: handle
        width: 28
        height: width
        radius: width / 2
        color: SelectionRectangle.dragging ? control.palette.light : control.palette.window
        border.width: 1
        border.color: control.enabled ? control.palette.mid : control.palette.midlight
        visible: SelectionRectangle.control.active

        property Item control: SelectionRectangle.control
    }

}
