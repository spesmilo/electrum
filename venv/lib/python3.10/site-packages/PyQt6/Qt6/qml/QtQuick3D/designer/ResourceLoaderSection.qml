// Copyright (C) 2023 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Resource Loader")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Geometries")
            Layout.alignment: Qt.AlignTop
            Layout.topMargin: 5
            tooltip: qsTr("A list of custom geometries to be loaded and cached.")
        }

        SecondColumnLayout {
            EditableListView {
                backendValue: backendValues.geometries
                model: backendValues.geometries.expressionAsList
                Layout.fillWidth: true
                typeFilter: "QtQuick3D.Geometry"

                onAdd: function(value) { backendValues.geometries.idListAdd(value) }
                onRemove: function(idx) { backendValues.geometries.idListRemove(idx) }
                onReplace: function (idx, value) { backendValues.geometries.idListReplace(idx, value) }
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Mesh Sources")
            Layout.alignment: Qt.AlignTop
            Layout.topMargin: 5
            tooltip: qsTr("A list of mesh assets to be loaded and cached.")
        }

        SecondColumnLayout {

            ActionIndicator {
                    icon.color: extFuncLogic.color
                    icon.text: extFuncLogic.glyph
                    onClicked: extFuncLogic.show()
                    forceVisible: extFuncLogic.menuVisible
                ExtendedFunctionLogic {
                    id: extFuncLogic
                    backendValue: backendValues.meshSources
                }
            }

            // Placeholder until we can do list of value types: QDS-9090
            Label {
                text: qsTr("Currently only editable in QML.")
                Layout.fillWidth: true
                Layout.preferredWidth: StudioTheme.Values.singleControlColumnWidth
                Layout.minimumWidth: StudioTheme.Values.singleControlColumnWidth
                Layout.maximumWidth: StudioTheme.Values.singleControlColumnWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Textures")
            Layout.alignment: Qt.AlignTop
            Layout.topMargin: 5
            tooltip: qsTr("A list of textures to be loaded and cached.")
        }

        SecondColumnLayout {
            EditableListView {
                backendValue: backendValues.textures
                model: backendValues.textures.expressionAsList
                Layout.fillWidth: true
                typeFilter: "QtQuick3D.Texture"

                onAdd: function(value) { backendValues.textures.idListAdd(value) }
                onRemove: function(idx) { backendValues.textures.idListRemove(idx) }
                onReplace: function (idx, value) { backendValues.textures.idListReplace(idx, value) }
            }

            ExpandingSpacer {}
        }
    }
}
