// Copyright (C) 2023 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.Material
import QtQuick.Layouts
import QtQuick.Dialogs.quickimpl as DialogsQuickImpl

DialogsQuickImpl.ColorInputsImpl {
    id: control
    implicitWidth: implicitBackgroundWidth + leftInset + rightInset
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)
    padding: 1
    mode: colorSystemComboBox.currentIndex

    delegate: TextField {
        Layout.fillWidth: true
        Material.containerStyle: Material.Filled
        leftPadding: control.showAlpha && control.mode !== ColorInputs.Hex ? 1 : Material.textFieldHorizontalPadding / 2
        rightPadding: control.showAlpha && control.mode !== ColorInputs.Hex ? 1 : Material.textFieldHorizontalPadding / 2
    }

    contentItem: RowLayout {
        ComboBox {
            id: colorSystemComboBox
            objectName: "colorSystemComboBox"
            editable: false
            flat: true
            background.implicitWidth: 0
            implicitContentWidthPolicy: ComboBox.WidestTextWhenCompleted
            currentIndex: DialogsQuickImpl.ColorInputsImpl.Hex
            model: [qsTr("Hex"), qsTr("RGB"), qsTr("HSV"), qsTr("HSL")]
        }
    }
}
