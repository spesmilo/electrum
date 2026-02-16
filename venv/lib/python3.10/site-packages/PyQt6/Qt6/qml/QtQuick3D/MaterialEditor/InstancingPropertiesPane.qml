// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only WITH Qt-GPL-exception-1.0

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick3D
import Qt.labs.platform

Pane {
    id: root
    required property InstanceListEntry instanceEntry
    required property Model targetModel

    ColumnLayout {
        CheckBox {
            id: enableInstCheckBox
            text: qsTr("Enable Instancing")
            onCheckStateChanged: {
                targetModel.enableInstancing = checkState == Qt.Checked
            }
        }
        ColumnLayout {
            visible: targetModel.enableInstancing
            RowLayout {
                Label {
                    text: qsTr("Color")
                    Layout.fillWidth: true
                }
                Button {
                    id: colorButton
                    text: qsTr("Instancing Color")
                    Layout.fillWidth: true
                    background: Rectangle {
                        radius: 10
                        color: root.instanceEntry.color
                    }
                    onClicked: {
                        colorDialog.open()
                    }
                }
                ColorDialog {
                    id: colorDialog
                    currentColor: root.instanceEntry.color
                    onAccepted: root.instanceEntry.color = color
                }
            }
            RowLayout {
                Label {
                    text: qsTr("CustomData.x")
                    Layout.fillWidth: true
                }
                TextField {
                    id: customXInput
                    Layout.fillWidth: true
                    validator: DoubleValidator { locale: "C" }
                    onEditingFinished: {
                        if (acceptableInput)
                            root.instanceEntry.customData.x = parseFloat(text)
                    }
                }
            }
            RowLayout {
                Label {
                    text: qsTr("CustomData.y")
                    Layout.fillWidth: true
                }
                TextField {
                    id: customYInput
                    Layout.fillWidth: true
                    validator: DoubleValidator { locale: "C" }
                    onEditingFinished: {
                        if (acceptableInput)
                            root.instanceEntry.customData.y = parseFloat(text)
                    }
                }
            }
            RowLayout {
                Label {
                    text: qsTr("CustomData.z")
                    Layout.fillWidth: true
                }
                TextField {
                    id: customZInput
                    Layout.fillWidth: true
                    validator: DoubleValidator { locale: "C" }
                    onEditingFinished: {
                        if (acceptableInput)
                            root.instanceEntry.customData.z = parseFloat(text)
                    }
                }
            }
            RowLayout {
                Label {
                    text: qsTr("CustomData.w")
                    Layout.fillWidth: true
                }
                TextField {
                    id: customWInput
                    Layout.fillWidth: true
                    validator: DoubleValidator { locale: "C" }
                    onEditingFinished: {
                        if (acceptableInput)
                            root.instanceEntry.customData.w = parseFloat(text)
                    }
                }
            }
        }
    }
}
