// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T

Rectangle {
    id: root
    implicitWidth: 16
    implicitHeight: 16
    radius: 8
    color: "transparent"
    border.color: picker.visualFocus ? "#0066ff" : (picker.pressed ? "#36383a" : "#454647")
    border.width: 1

    required property T.Control picker

    property alias handleColor: circle.color

    Rectangle {
        id: circle
        x: 1
        y: 1
        width: 14
        height: 14
        radius: 7
        color: "transparent"
        border.color: root.picker.visualFocus ? "#0066ff" : (root.picker.pressed ? "#86888a" : "#959697")
        border.width: 1
    }
}
