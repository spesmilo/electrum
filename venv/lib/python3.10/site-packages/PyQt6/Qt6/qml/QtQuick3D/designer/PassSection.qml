// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Pass")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Commands")
            tooltip: qsTr("Sets the render commands of the pass.")
            Layout.alignment: Qt.AlignTop
            Layout.topMargin: 5
        }

        SecondColumnLayout {
            EditableListView {
                backendValue: backendValues.commands
                model: backendValues.commands.expressionAsList
                Layout.fillWidth: true
                typeFilter: "QtQuick3D.Command"

                onAdd: function(value) { backendValues.commands.idListAdd(value) }
                onRemove: function(idx) { backendValues.commands.idListRemove(idx) }
                onReplace: function (idx, value) { backendValues.commands.idListReplace(idx, value) }
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Buffer")
            tooltip: qsTr("Sets the output buffer for the pass.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.Buffer"
                backendValue: backendValues.output
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Shaders")
            tooltip: qsTr("Sets the shaders for the pass.")
            Layout.alignment: Qt.AlignTop
            Layout.topMargin: 5
        }

        SecondColumnLayout {
            EditableListView {
                backendValue: backendValues.shaders
                model: backendValues.shaders.expressionAsList
                Layout.fillWidth: true
                typeFilter: "QtQuick3D.Shader"

                onAdd: function(value) { backendValues.shaders.idListAdd(value) }
                onRemove: function(idx) { backendValues.shaders.idListRemove(idx) }
                onReplace: function (idx, value) { backendValues.shaders.idListReplace(idx, value) }
            }

            ExpandingSpacer {}
        }
    }
}
