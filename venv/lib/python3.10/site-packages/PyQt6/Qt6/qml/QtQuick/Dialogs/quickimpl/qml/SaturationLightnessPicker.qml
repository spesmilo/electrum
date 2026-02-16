// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Dialogs
import QtQuick.Dialogs.quickimpl

SaturationLightnessPickerImpl {
    id: control

    implicitWidth: Math.max(background ? background.implicitWidth : 0, contentItem.implicitWidth)
    implicitHeight: Math.max(background ? background.implicitHeight : 0, contentItem.implicitHeight)

    background: Rectangle {
        anchors.fill: parent
        color: control.visualFocus ? (control.pressed ? "#cce0ff" : "#f0f6ff") : (control.pressed ? "#d6d6d6" : "#f6f6f6")
        border.color: "#353637"
    }

    contentItem: SaturationLightnessPickerCanvas {
        anchors.fill: parent
        hue: control.hue
    }

    handle: PickerHandle {
        x: control.leftPadding + control.lightness * control.availableWidth - width / 2
        y: control.topPadding + (1.0 - control.saturation) * control.availableHeight - height / 2
        picker: control
        handleColor: control.color
        z: 1
    }
}
