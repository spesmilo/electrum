// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Column {
    width: parent.width

    Section {
        caption: qsTr("Default Material")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Lighting")
                tooltip: qsTr("Sets the lighting method. NoLighting is faster while FragmentLighting\ncalculates diffuse and specular lighting for each rendered pixel.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "DefaultMaterial"
                    model: ["NoLighting", "FragmentLighting"]
                    backendValue: backendValues.lighting
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Blend Mode")
                tooltip: qsTr("Sets how the colors of the model blend with colors behind it.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "DefaultMaterial"
                    model: ["SourceOver", "Screen", "Multiply"]
                    backendValue: backendValues.blendMode
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Enable Vertex Colors")
                tooltip: qsTr("Sets the material to use vertex colors from the mesh.\nVertex colors are multiplied with any other color for the material.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.vertexColorsEnabled.valueToString
                    backendValue: backendValues.vertexColorsEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Point Size")
                tooltip: qsTr("Sets the size of the points rendered when the geometry is using a primitive type of points.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.pointSize
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }
            }

            PropertyLabel {
                text: qsTr("Line Width")
                tooltip: qsTr("Sets the width of the lines rendered when the geometry is using a primitive type of lines or line strips.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.lineWidth
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }
            }
        }
    }

    Section {
        caption: qsTr("Diffuse")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Color")
                tooltip: qsTr("Sets the base color.")
            }

            ColorEditor {
                backendValue: backendValues.diffuseColor
                supportGradient: false
            }

            PropertyLabel {
                text: qsTr("Map")
                tooltip: qsTr("Sets a texture to apply to the material.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.diffuseMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Emissive")
        width: parent.width

        ColumnLayout {
            spacing: StudioTheme.Values.transform3DSectionSpacing

            SectionLayout {
                PropertyLabel {
                    text: qsTr("Factor")
                    tooltip: qsTr("Sets the color of self-illumination.\nThe default value (0, 0, 0) means no self-illumination.")
                }

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: 0
                        maximumValue: 1
                        decimals: 2
                        stepSize: 0.01
                        backendValue: backendValues.emissiveFactor_x
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: qsTr("R")
                        color: StudioTheme.Values.theme3DAxisXColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: 0
                        maximumValue: 1
                        decimals: 2
                        stepSize: 0.01
                        backendValue: backendValues.emissiveFactor_y
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: qsTr("G")
                        color: StudioTheme.Values.theme3DAxisYColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: 0
                        maximumValue: 1
                        decimals: 2
                        stepSize: 0.01
                        backendValue: backendValues.emissiveFactor_z
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: qsTr("B")
                        color: StudioTheme.Values.theme3DAxisZColor
                    }

                    ExpandingSpacer {}
                }
                PropertyLabel {
                    text: qsTr("Map")
                    tooltip: qsTr("Sets a texture to define the intensity of the emissive color.")
                }

                SecondColumnLayout {
                    ItemFilterComboBox {
                        typeFilter: "QtQuick3D.Texture"
                        backendValue: backendValues.emissiveMap
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    ExpandingSpacer {}
                }
            }
        }
    }

    Section {
        caption: qsTr("Specular")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Tint")
                tooltip: qsTr("Sets the color tint for the specular reflections.\nUse white for no color effect.")
            }

            ColorEditor {
                backendValue: backendValues.specularTint
                supportGradient: false
            }

            PropertyLabel {
                text: qsTr("Amount")
                tooltip: qsTr("Sets the strength of specularity (highlights and reflections).\nThe default value (0) disables specularity.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.specularAmount
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Map")
                tooltip: qsTr("Sets a texture to define the amount and the color of specularity.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.specularMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Model")
                tooltip: qsTr("Sets the functions to calculate specular highlights for lights in the scene.\nDefault is faster while KGGX is more physically accurate.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "DefaultMaterial"
                    model: ["Default", "KGGX"]
                    backendValue: backendValues.specularModel
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                    + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Reflection Map")
                tooltip: qsTr("Sets a texture to define specular highlights.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.specularReflectionMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Index of Refraction")
                tooltip: qsTr("Sets the angles of reflections affected by the fresnel power.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 1
                    maximumValue: 3
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.indexOfRefraction
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Fresnel Power")
                tooltip: qsTr("Sets the strength of the fresnel power. The default value (0) means no fresnel power while a higher value\ndecreases head-on reflections (looking directly at the surface) while maintaining reflections seen at grazing angles.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.fresnelPower
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Specular Roughness")
                tooltip: qsTr("Sets the size of the specular highlight generated from lights and the clarity of reflections in general.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0.001
                    maximumValue: 1
                    decimals: 3
                    stepSize: 0.1
                    backendValue: backendValues.specularRoughness
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Roughness Map")
                tooltip: qsTr("Sets a texture to define the specular roughness.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.roughnessMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Roughness Channel")
                tooltip: qsTr("Sets the texture channel to read the roughness value from roughnessMap.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "Material"
                    model: ["R", "G", "B", "A"]
                    backendValue: backendValues.roughnessChannel
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Opacity")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Amount")
                tooltip: qsTr("Sets the opacity of just this material, separate from the model.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.opacity
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Map")
                tooltip: qsTr("Sets a texture to control the opacity differently for different parts.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.opacityMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Channel")
                tooltip: qsTr("Sets the texture channel to read the opacity value from the opacity map.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "Material"
                    model: ["R", "G", "B", "A"]
                    backendValue: backendValues.opacityChannel
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Bump/Normal")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Bump Amount")
                tooltip: qsTr("Sets the amount of simulated displacement for the bump map or normal map.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.bumpAmount
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Bump Map")
                tooltip: qsTr("Sets a grayscale texture to simulate fine geometry displacement across the surface.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    id: bumpMapComboBox
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.bumpMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth

                    Connections {
                        target: normalMapComboBox.backendValue
                        function onExpressionChanged() {
                            if (normalMapComboBox.backendValue.expression !== "")
                                bumpMapComboBox.backendValue.resetValue()
                        }
                    }
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Normal Map")
                tooltip: qsTr("Sets a image to simulate fine geometry displacement across the surface.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    id: normalMapComboBox
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.normalMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth

                    Connections {
                        target: bumpMapComboBox.backendValue
                        function onExpressionChanged() {
                            if (bumpMapComboBox.backendValue.expression !== "")
                                normalMapComboBox.backendValue.resetValue()
                        }
                    }
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Translucency")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Falloff")
                tooltip: qsTr("Sets the amount of falloff for the translucency based on the angle of the normals of the object to the light source.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -999999
                    maximumValue: 999999
                    decimals: 2
                    backendValue: backendValues.translucentFalloff
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Diffuse Light Wrap")
                tooltip: qsTr("Sets the amount of light wrap for the translucency map.\nA value of 0 will not wrap the light at all, while a value of 1 will wrap the light all around the object.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.diffuseLightWrap
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Map")
                tooltip: qsTr("Sets a grayscale texture to control how much light can pass through the material from behind.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.translucencyMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Channel")
                tooltip: qsTr("Sets the texture channel to read the translucency value from translucencyMap.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "Material"
                    model: ["R", "G", "B", "A"]
                    backendValue: backendValues.translucencyChannel
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }
}
