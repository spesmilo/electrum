// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Column {
    width: parent.width

    Section {
        caption: qsTr("Model")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Source")
                tooltip: qsTr("Sets the location of the mesh file containing the geometry of this model.")
            }

            SecondColumnLayout {
                UrlChooser {
                    id: sourceUrlChooser
                    backendValue: backendValues.source
                    filter: "*.mesh"
                    defaultItems: ["#Rectangle" ,"#Sphere" ,"#Cube" ,"#Cone" ,"#Cylinder"]
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Geometry")
                tooltip: qsTr("Sets a custom geometry for the model")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    id: geometryComboBox
                    typeFilter: "QtQuick3D.Geometry"
                    backendValue: backendValues.geometry
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth

                    Connections {
                        target: geometryComboBox.backendValue
                        function onExpressionChanged() {
                            if (geometryComboBox.backendValue.expression !== "" &&
                                    sourceUrlChooser.backendValue.expression !== "")
                                sourceUrlChooser.backendValue.resetValue()
                        }
                    }
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Materials")
                Layout.alignment: Qt.AlignTop
                Layout.topMargin: 5
            }

            SecondColumnLayout {
                EditableListView {
                    backendValue: backendValues.materials
                    model: backendValues.materials.expressionAsList
                    Layout.fillWidth: true
                    typeFilter: "QtQuick3D.Material"
                    textRole: "idAndName"

                    onAdd: function(value) { backendValues.materials.idListAdd(value) }
                    onRemove: function(idx) { backendValues.materials.idListRemove(idx) }
                    onReplace: function (idx, value) { backendValues.materials.idListReplace(idx, value) }

                    extraButtonIcon: StudioTheme.Constants.material_medium
                    extraButtonToolTip: qsTr("Edit material")
                    onExtraButtonClicked: (idx) => { backendValues.materials.openMaterialEditor(idx) }
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Casts Shadows")
                tooltip: qsTr("Enables the geometry of this model to be rendered to the shadow maps.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.castsShadows.valueToString
                    backendValue: backendValues.castsShadows
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Receives Shadows")
                tooltip: qsTr("Enables the geometry of this model to receive shadows.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.receivesShadows.valueToString
                    backendValue: backendValues.receivesShadows
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Casts Reflections")
                tooltip: qsTr("Enables reflection probes to reflect this model.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.castsReflections.valueToString
                    backendValue: backendValues.castsReflections
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Receives Reflections")
                tooltip: qsTr("Enables the geometry of this model to receive reflections from the nearest reflection probe. The model must be inside at least one reflection probe to start receiving reflections.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.receivesReflections.valueToString
                    backendValue: backendValues.receivesReflections
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Is Pickable")
                tooltip: qsTr("Enables ray cast based picking for this model.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.pickable.valueToString
                    backendValue: backendValues.pickable
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Used in Baked Lighting")
                tooltip: qsTr("This model is static and suitable to contribute to baked lighting.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.usedInBakedLighting.valueToString
                    backendValue: backendValues.usedInBakedLighting
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }


            PropertyLabel {
                text: qsTr("Depth Bias")
                tooltip: qsTr("Sets the depth bias of the model.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 0
                    backendValue: backendValues.depthBias
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("LOD Bias")
                tooltip: qsTr("Sets the size a model needs to be when rendered before the automatic level of detail meshes are used")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0.0
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.levelOfDetailBias
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Instancing")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Data Source")
                tooltip: qsTr("If this property is set, the model will not be rendered normally. Instead, a number of instances of the model will be rendered, as defined by the instance table.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Instancing"
                    backendValue: backendValues.instancing
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Origin Node")
                tooltip: qsTr("Sets the origin of the instance’s coordinate system.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Node"
                    backendValue: backendValues.instanceRoot
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Animation")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Skeleton")
                tooltip: qsTr("Sets the skeleton for the model.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Skeleton"
                    backendValue: backendValues.skeleton
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Morph Targets")
                tooltip: qsTr("Sets a list of MorphTargets used to render the provided geometry.")
                Layout.alignment: Qt.AlignTop
                Layout.topMargin: 5
            }

            SecondColumnLayout {
                EditableListView {
                    backendValue: backendValues.morphTargets
                    model: backendValues.morphTargets.expressionAsList
                    Layout.fillWidth: true
                    typeFilter: "QtQuick3D.MorphTarget"

                    onAdd: function(value) { backendValues.morphTargets.idListAdd(value) }
                    onRemove: function(idx) { backendValues.morphTargets.idListRemove(idx) }
                    onReplace: function (idx, value) { backendValues.morphTargets.idListReplace(idx, value) }
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Skin")
                tooltip: qsTr("Sets the skin for the model.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Skin"
                    backendValue: backendValues.skin
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Lightmapping")
        width: parent.width

        SectionLayout {

            PropertyLabel {
                text: qsTr("Resolution")
                tooltip: qsTr("Sets the target resolution of the baked lightmap texture for the model.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 128
                    maximumValue: 4096
                    decimals: 0
                    stepSize: 128
                    sliderIndicatorVisible: true
                    backendValue: backendValues.lightmapBaseResolution
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Lightmap")
                tooltip: qsTr("Sets the baked lightmap data for the model.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.BakedLightmap"
                    backendValue: backendValues.bakedLightmap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }
}
