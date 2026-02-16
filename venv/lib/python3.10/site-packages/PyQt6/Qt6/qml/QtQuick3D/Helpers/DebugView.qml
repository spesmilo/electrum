// Copyright (C) 2023 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick3D
import QtQuick3D.Helpers.impl

Pane {
    id: root
    property var source: null
    property bool resourceDetailsVisible: false
    opacity: 0.9

    ColumnLayout {
        id: layout
        RowLayout {
            Label {
                Layout.fillWidth: true
                text: root.source.renderStats.fps + " FPS"
                font.pointSize: 14
            }

            Label {
                text: "Details"
            }

            CheckBox {
                checked: root.resourceDetailsVisible
                onCheckedChanged: {
                    resourceDetailsVisible = checked;
                }
            }
        }

        component TimeLabel : RowLayout {
            id: timeLabel
            property alias text: label.text
            property real value: 0.0
            Label {
                id: label
                Layout.fillWidth: true
                text: "Frame: "

            }
            Label {
                text: timeLabel.value.toFixed(3) + "ms"
            }
        }

        TimeLabel {
            text: "Frame: "
            value: root.source.renderStats.frameTime
        }

        TimeLabel {
            text: "    Sync: "
            value: root.source.renderStats.syncTime
        }

        TimeLabel {
            text: "    Prep: "
            value: root.source.renderStats.renderPrepareTime
        }

        TimeLabel {
            text: "    Render: "
            value: root.source.renderStats.renderTime
        }

        TimeLabel {
            text: "Max: "
            value: root.source.renderStats.maxFrameTime
        }

        TimeLabel {
            text: "GPU: "
            value: root.source.renderStats.lastCompletedGpuTime
            visible: root.source.renderStats.lastCompletedGpuTime > 0
        }

        Page {
            Layout.fillWidth: true
            Layout.minimumWidth: 530
            visible: root.resourceDetailsVisible
            header: TabBar {
                id: tabBar
                TabButton {
                    text: "Summary"
                }
                TabButton {
                    text: "Passes"
                }
                TabButton {
                    text: "Textures"
                }
                TabButton {
                    text: "Meshes"
                }
                TabButton {
                    text: "Tools"
                }
                TabButton {
                    text: "Shadows"
                }
            }

            StackLayout {
                anchors.fill: parent
                anchors.margins: 10
                currentIndex: tabBar.currentIndex

                Pane {
                    id: summaryPane
                    ColumnLayout {
                        Label {
                            text: "Graphics API: " + root.source.renderStats.graphicsApiName
                            visible: root.resourceDetailsVisible
                        }
                        Label {
                            text: root.source.renderStats.renderPassCount + " render passes"
                            visible: root.resourceDetailsVisible
                        }
                        Label {
                            text: root.source.renderStats.drawCallCount + " draw calls"
                            visible: root.resourceDetailsVisible
                        }
                        Label {
                            text: root.source.renderStats.drawVertexCount + " vertices"
                            visible: root.resourceDetailsVisible
                        }
                        Label {
                            text: "Image assets: " + (root.source.renderStats.imageDataSize / 1024).toFixed(2) + " KB"
                            visible: root.resourceDetailsVisible
                        }
                        Label {
                            text: "Mesh assets: " + (root.source.renderStats.meshDataSize / 1024).toFixed(2) + " KB"
                            visible: root.resourceDetailsVisible
                        }
                        Label {
                            text: "Pipelines: " + root.source.renderStats.pipelineCount
                            visible: root.resourceDetailsVisible
                        }
                        Label {
                            text: "Material build time: " + root.source.renderStats.materialGenerationTime + " ms"
                            visible: root.resourceDetailsVisible
                        }
                        Label {
                            text: "Effect build time: " + root.source.renderStats.effectGenerationTime + " ms"
                            visible: root.resourceDetailsVisible
                        }
                        Label {
                            text: "Pipeline build time: " + root.source.renderStats.pipelineCreationTime + " ms"
                            visible: root.resourceDetailsVisible
                        }
                        Label {
                            text: root.source.renderStats.vmemAllocCount + " vmem allocs with " + root.source.renderStats.vmemUsedBytes + " bytes"
                            visible: root.resourceDetailsVisible && root.source.renderStats.vmemAllocCount > 0
                        }
                    }
                }

                Pane {
                    id: passesPane
                    RenderStatsPassesModel {
                        id: passesModel
                        passData: root.source.renderStats.renderPassDetails
                    }
                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 0
                        HorizontalHeaderView {
                            syncView: passesTableView
                            resizableColumns: false // otherwise QTBUG-111013 happens
                            boundsBehavior: Flickable.StopAtBounds
                            flickableDirection: Flickable.VerticalFlick
                        }
                        ListModel {
                            id: passesHeaderModel
                            ListElement {
                                columnWidth: 300 // name
                            }
                            ListElement {
                                columnWidth: 80 // size
                            }
                            ListElement {
                                columnWidth: 60 // vertices
                            }
                            ListElement {
                                columnWidth: 60 // draw calls
                            }
                        }
                        Item {
                            Layout.fillHeight: true
                            Layout.fillWidth: true
                            TableView {
                                id: passesTableView
                                anchors.fill: parent
                                // name, size, vertices, draw calls
                                property var columnFactors: [58, 14, 12, 12]; // == 96, leave space for the scrollbar
                                columnWidthProvider: function (column) {
                                    return passesPane.width * (columnFactors[column] / 100.0);
                                }
                                boundsBehavior: Flickable.StopAtBounds
                                flickableDirection: Flickable.VerticalFlick
                                ScrollBar.vertical: ScrollBar {
                                    parent: passesTableView.parent
                                    anchors.top: passesTableView.top
                                    anchors.bottom: passesTableView.bottom
                                    anchors.left: passesTableView.right
                                }
                                clip: true
                                model: passesModel
                                columnSpacing: 1
                                rowSpacing: 1
                                implicitWidth: parent.width + columnSpacing
                                implicitHeight: parent.height + rowSpacing
                                delegate: CustomTableItemDelegate {
                                    required property string display
                                    text: display
                                    color: TableView.view.palette.base
                                    textColor: TableView.view.palette.text
                                }
                            }
                        }
                    }
                }

                Pane {
                    id: texturesPane
                    RenderStatsTexturesModel {
                        id: texturesModel
                        textureData: root.source.renderStats.textureDetails
                    }
                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 0
                        HorizontalHeaderView {
                            syncView: texturesTableView
                            resizableColumns: false // otherwise QTBUG-111013 happens
                            boundsBehavior: Flickable.StopAtBounds
                            flickableDirection: Flickable.VerticalFlick
                        }
                        Item {
                            Layout.fillHeight: true
                            Layout.fillWidth: true
                            TableView {
                                id: texturesTableView
                                anchors.fill: parent
                                // name, size, format, miplevels, flags
                                property var columnFactors: [48, 12, 12, 12, 12]; // == 96, leave space for the scrollbar
                                columnWidthProvider: function (column) {
                                    return texturesPane.width * (columnFactors[column] / 100.0);
                                }
                                boundsBehavior: Flickable.StopAtBounds
                                flickableDirection: Flickable.VerticalFlick
                                ScrollBar.vertical: ScrollBar {
                                    parent: texturesTableView.parent
                                    anchors.top: texturesTableView.top
                                    anchors.bottom: texturesTableView.bottom
                                    anchors.left: texturesTableView.right
                                }
                                ScrollBar.horizontal: ScrollBar { }
                                clip: true
                                model: texturesModel
                                columnSpacing: 1
                                rowSpacing: 1
                                implicitWidth: parent.width + columnSpacing
                                implicitHeight: parent.height + rowSpacing
                                delegate: CustomTableItemDelegate {
                                    required property string display
                                    text: display
                                    color: TableView.view.palette.base
                                    textColor: TableView.view.palette.text
                                }
                            }
                        }
                    }
                }

                Pane {
                    id: meshesPane
                    RenderStatsMeshesModel {
                        id: meshesModel
                        meshData: root.source.renderStats.meshDetails
                    }
                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 0
                        HorizontalHeaderView {
                            syncView: meshesTableView
                            resizableColumns: false // otherwise QTBUG-111013 happens
                            boundsBehavior: Flickable.StopAtBounds
                            flickableDirection: Flickable.VerticalFlick
                        }
                        Item {
                            Layout.fillHeight: true
                            Layout.fillWidth: true
                            TableView {
                                id: meshesTableView
                                anchors.fill: parent
                                // name, submeshes, vertices, vbufsize, ibufsize
                                property var columnFactors: [48, 12, 12, 12, 12]; // == 96, leave space for the scrollbar
                                columnWidthProvider: function (column) {
                                    return meshesPane.width * (columnFactors[column] / 100.0);
                                }
                                boundsBehavior: Flickable.StopAtBounds
                                flickableDirection: Flickable.VerticalFlick
                                ScrollBar.vertical: ScrollBar {
                                    parent: meshesTableView.parent
                                    anchors.top: meshesTableView.top
                                    anchors.bottom: meshesTableView.bottom
                                    anchors.left: meshesTableView.right
                                }
                                clip: true
                                model: meshesModel
                                columnSpacing: 1
                                rowSpacing: 1
                                implicitWidth: parent.width + columnSpacing
                                implicitHeight: parent.height + rowSpacing
                                delegate: CustomTableItemDelegate {
                                    required property string display
                                    text: display
                                    color: TableView.view.palette.base
                                    textColor: TableView.view.palette.text
                                }
                            }
                        }
                    }
                }

                Pane {
                    id: visualizePane
                    ColumnLayout {
                        id: visCtrCol
                        width: parent.width
                        CheckBox {
                            text: "Wireframe mode"
                            onCheckedChanged: root.source.environment.debugSettings.wireframeEnabled = checked
                        }
                        RowLayout {
                            Label {
                                text: "Material override"
                            }
                            ComboBox {
                                id: materialOverrideComboBox
                                textRole: "text"
                                valueRole: "value"
                                implicitContentWidthPolicy: ComboBox.WidestText
                                onActivated: root.source.environment.debugSettings.materialOverride = currentValue
                                Component.onCompleted: materialOverrideComboBox.currentIndex = materialOverrideComboBox.indexOfValue(root.source.environment.debugSettings.materialOverride)
                                model: [
                                    { value: DebugSettings.None, text: "None"},
                                    { value: DebugSettings.BaseColor, text: "Base Color"},
                                    { value: DebugSettings.Roughness, text: "Roughness"},
                                    { value: DebugSettings.Metalness, text: "Metalness"},
                                    { value: DebugSettings.Diffuse, text: "Diffuse"},
                                    { value: DebugSettings.Specular, text: "Specular"},
                                    { value: DebugSettings.ShadowOcclusion, text: "Shadow Occlusion"},
                                    { value: DebugSettings.Emission, text: "Emission"},
                                    { value: DebugSettings.AmbientOcclusion, text: "Ambient Occlusion"},
                                    { value: DebugSettings.Normals, text: "Normals"},
                                    { value: DebugSettings.Tangents, text: "Tangents"},
                                    { value: DebugSettings.Binormals, text: "Binormals"},
                                    { value: DebugSettings.F0, text: "F0"}
                                ]
                            }
                        }
                        RowLayout {
                            spacing: 20
                            Button {
                                text: "Release cached resources"
                                onClicked: root.source.renderStats.releaseCachedResources()
                            }
                            Button {
                                text: "Bake lightmap"
                                onClicked: root.source.bakeLightmap()
                            }
                            Button {
                                text: "Denoise lightmap"
                                onClicked: root.source.denoiseLightmap()
                            }
                        }
                        RowLayout {
                            Label {
                                text: "Render mode override"
                            }
                            ComboBox {
                                id: renderModeOverrideComboBox
                                textRole: "text"
                                valueRole: "value"
                                implicitContentWidthPolicy: ComboBox.WidestText
                                onActivated: root.source.renderMode = currentValue
                                Component.onCompleted: renderModeOverrideComboBox.currentIndex = renderModeOverrideComboBox.indexOfValue(root.source.renderMode)
                                model: [
                                    { value: View3D.Offscreen, text: "Offscreen" },
                                    { value: View3D.Underlay, text: "Underlay" },
                                    { value: View3D.Overlay, text: "Overlay" },
                                    { value: View3D.Inline, text: "Inline" }
                                ]
                            }
                        }

                        Label {
                            text: "View3D logical size is " + root.source.width + "x" + root.source.height
                        }
                        Label {
                            text: "Backing texture pixel size is " + root.source.effectiveTextureSize.width + "x" + root.source.effectiveTextureSize.height
                            visible: root.source.renderMode === View3D.Offscreen
                        }
                        RowLayout {
                            CheckBox {
                                id: explicitTextureSizeCheckBox
                                visible: root.source.renderMode === View3D.Offscreen
                                text: "Explicit backing texture size"
                                property real aspectRatio: root.source.width / root.source.height
                                onCheckedChanged: updateSize()
                                function updateSize() {
                                    if (!explicitTextureSizeCheckBox.checked) {
                                        root.source.explicitTextureWidth = 0;
                                        root.source.explicitTextureHeight = 0;
                                        return;
                                    }
                                    var newWidth = explicitWidthSlider.value;
                                    var newHeight = explicitHeightSlider.value;
                                    if (keepAspectRatioCheckBox.checked) {
                                        var aspectRatio = explicitTextureSizeCheckBox.aspectRatio;
                                        if (newHeight * aspectRatio <= newWidth)
                                            newWidth = newHeight * aspectRatio;
                                        else
                                            newHeight = newWidth * (1.0 / aspectRatio);
                                    }
                                    root.source.explicitTextureWidth = newWidth;
                                    root.source.explicitTextureHeight = newHeight;
                                }
                                Connections {
                                    target: root.source
                                    function onWidthChanged() { explicitTextureSizeCheckBox.updateSize() }
                                    function onHeightChanged() { explicitTextureSizeCheckBox.updateSize() }
                                }
                            }
                            CheckBox {
                                id: keepAspectRatioCheckBox
                                visible: root.source.renderMode === View3D.Offscreen && explicitTextureSizeCheckBox.checked
                                text: "Keep aspect ratio (" + explicitTextureSizeCheckBox.aspectRatio.toFixed(2) + ")"
                                checked: false
                                onCheckedChanged: explicitTextureSizeCheckBox.updateSize()
                            }
                        }
                        RowLayout {
                            visible: root.source.renderMode === View3D.Offscreen && explicitTextureSizeCheckBox.checked
                            Label {
                                text: "Width: " + explicitWidthSlider.value.toFixed(0) + " px"
                            }
                            Slider {
                                id: explicitWidthSlider
                                from: 16
                                to: 4096
                                value: 1280
                                onValueChanged: explicitTextureSizeCheckBox.updateSize()
                                Layout.maximumWidth: 120
                            }
                            Label {
                                text: "Height: " + explicitHeightSlider.value.toFixed(0) + " px"
                            }
                            Slider {
                                id: explicitHeightSlider
                                from: 16
                                to: 4096
                                value: 720
                                onValueChanged: explicitTextureSizeCheckBox.updateSize()
                                Layout.maximumWidth: 120
                            }
                        }
                    }
                }

                Pane {
                    id: shadowsPane
                    ColumnLayout {
                        width: parent.width
                        CheckBox {
                            text: "Draw directional light shadow bounding boxes"
                            checked: root.source.environment.debugSettings.drawDirectionalLightShadowBoxes
                            onCheckedChanged: root.source.environment.debugSettings.drawDirectionalLightShadowBoxes = checked
                        }
                        CheckBox {
                            text: "Draw point light shadow bounding boxes"
                            checked: root.source.environment.debugSettings.drawPointLightShadowBoxes
                            onCheckedChanged: root.source.environment.debugSettings.drawPointLightShadowBoxes = checked
                        }
                        CheckBox {
                            text: "Draw shadow casting bounding box"
                            checked: root.source.environment.debugSettings.drawShadowCastingBounds
                            onCheckedChanged: root.source.environment.debugSettings.drawShadowCastingBounds = checked
                        }
                        CheckBox {
                            text: "Draw shadow receiving bounding box"
                            checked: root.source.environment.debugSettings.drawShadowReceivingBounds
                            onCheckedChanged: root.source.environment.debugSettings.drawShadowReceivingBounds = checked
                        }
                        CheckBox {
                            text: "Draw cascades"
                            checked: root.source.environment.debugSettings.drawCascades
                            onCheckedChanged: root.source.environment.debugSettings.drawCascades = checked
                        }
                        CheckBox {
                            text: "Draw scene cascade intersection"
                            checked: root.source.environment.debugSettings.drawSceneCascadeIntersection
                            onCheckedChanged: root.source.environment.debugSettings.drawSceneCascadeIntersection = checked
                        }
                        CheckBox {
                            text: "Disable Shadow Camera Update"
                            checked: root.source.environment.debugSettings.disableShadowCameraUpdate
                            onCheckedChanged: root.source.environment.debugSettings.disableShadowCameraUpdate = checked
                        }
                    }
                }
            }
        }
    }

    component CustomTableItemDelegate : Rectangle {
        property alias text: textLabel.text
        property alias textColor: textLabel.color
        implicitWidth: 100
        implicitHeight: textLabel.implicitHeight + 4
        color: palette.base
        Label {
            id: textLabel
            anchors.centerIn: parent
            color: palette.text
        }
    }

    function syncVisible() {
        if (source) {
            source.renderStats.extendedDataCollectionEnabled = visible && resourceDetailsVisible;
            if (source.renderStats.extendedDataCollectionEnabled)
                source.update();
        }
    }

    Component.onCompleted: syncVisible()
    onSourceChanged: syncVisible()
    onVisibleChanged: syncVisible()
    onResourceDetailsVisibleChanged: syncVisible()
}
