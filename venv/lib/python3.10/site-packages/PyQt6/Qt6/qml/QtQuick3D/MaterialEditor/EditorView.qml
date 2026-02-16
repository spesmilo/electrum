// Copyright (C) 2023 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only WITH Qt-GPL-exception-1.0

import QtQuick
import QtQuick.Window
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick3D.MaterialEditor
import QtQuick3D

SplitView {
    id: editorView
    orientation: Qt.Vertical
    property alias vertexEditor: vertEdit
    property alias fragmentEditor: fragEdit
    property alias outputTextItem: outputTextItem
    property alias outputView: outputView
    property alias vertexTabText: vertexTabText.text
    property alias fragmentTabText: fragTabtext.text
    property alias infoStack: infoStack
    property alias tabBarInfoView: tabBarInfoView
    property alias tabButtonShaderOutput: tabButtonShaderOutput
    property alias uniformModel: uniformManagerPane.uniformModel
    required property MaterialAdapter materialAdapter
    required property InstanceListEntry instanceEntry
    required property Model targetModel

    ColumnLayout {
        SplitView.preferredHeight: parent.height * .8
        TabBar {
            id: tabBarEditors
            Layout.fillWidth: true
            readonly property string defVertText: qsTr("Vertex")
            readonly property string defFragText: qsTr("Fragment")
            TabButton {
                id: vertexTabText
                onTextChanged: {
                    if (text === "")
                        text = tabBarEditors.defVertText
                }
            }
            TabButton {
                id: fragTabtext
                onTextChanged: {
                    if (text === "")
                        text = tabBarEditors.defFragText
                }
            }
            TabButton {
                id: matPropTabText
                text: qsTr("Material Properties")
            }
            TabButton {
                id: instPropTabText
                text: qsTr("Instancing Properties")
            }
        }

        // Editors
        StackLayout {
            id: editorStack
            currentIndex: tabBarEditors.currentIndex
            Layout.fillWidth: true

            ShaderEditor {
                id: vertEdit
                Layout.fillHeight: true
                Layout.fillWidth: true
            }
            ShaderEditor {
                id: fragEdit
                Layout.fillHeight: true
                Layout.fillWidth: true
            }

            MaterialPropertiesPane {
                id: matPropPane
                targetMaterial: editorView.materialAdapter
                Layout.fillHeight: true
                Layout.fillWidth: true
            }

            InstancingPropertiesPane {
                id: instPropPane
                instanceEntry: editorView.instanceEntry
                targetModel: editorView.targetModel
                Layout.fillHeight: true
                Layout.fillWidth: true
            }
        }
    }

    ColumnLayout {
        spacing: 0
        TabBar {
            id: tabBarInfoView
            Layout.fillWidth: true
            TabButton {
                id: tabButtonUniforms
                text: qsTr("Uniforms")
            }
            TabButton {
                id: tabButtonShaderOutput
                text: qsTr("Shader Output")
            }
        }

        // Uniform, compile output etc.
        StackLayout {
            id: infoStack
            currentIndex: tabBarInfoView.currentIndex
//            Layout.preferredHeight: parent.height * .2
            Layout.fillWidth: true
            UniformManagerPane {
                id: uniformManagerPane
                materialAdapter: editorView.materialAdapter
                Layout.fillHeight: true
                Layout.fillWidth: true
            }
            Rectangle {
                id: outputView
                Layout.fillHeight: true
                Layout.fillWidth: true
                color: palette.base
                ScrollView {
                    anchors.fill: parent
                    ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
                    ScrollBar.vertical.policy: ScrollBar.AlwaysOn
                    TextArea {
                        id: outputTextItem
                        width: outputView.width
                        padding: 2
                        color: palette.text
                        wrapMode: Text.WordWrap
                        readOnly: true
                        text: " "
                    }
                }
                Button {
                    anchors.right: parent.right
                    anchors.rightMargin: 25
                    anchors.bottom: parent.bottom
                    anchors.bottomMargin: 5
                    text: qsTr("Clear")
                    onClicked: {
                        outputTextItem.text = "";
                    }
                }
            }
        }
    }
}
