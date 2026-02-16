// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Column {
    width: parent.width

    Section {
        caption: qsTr("Specular Glossy Material")
        width: parent.width

        SectionLayout {
            id: baseSectionLayout
            property bool isAlphaMaskMode: alphaModeComboBox.currentIndex === 1
            PropertyLabel {
                text: qsTr("Alpha Mode")
                tooltip: qsTr("Sets the mode for how the alpha channel of material color is used.")
            }

            SecondColumnLayout {
                ComboBox {
                    id: alphaModeComboBox
                    scope: "SpecularGlossyMaterial"
                    model: ["Default", "Mask", "Blend", "Opaque"]
                    backendValue: backendValues.alphaMode
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: baseSectionLayout.isAlphaMaskMode
                text: qsTr("Alpha Cutoff")
                tooltip: qsTr("Sets the cutoff value when using the Mask alphaMode.")
            }

            SecondColumnLayout {
                visible: baseSectionLayout.isAlphaMaskMode
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.alphaCutoff
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Blend Mode")
                tooltip: qsTr("Sets how the colors of the model rendered blend with those behind it.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "SpecularGlossyMaterial"
                    model: ["SourceOver", "Screen", "Multiply"]
                    backendValue: backendValues.blendMode
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Lighting")
                tooltip: qsTr("Sets which lighting method is used when generating this material.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "SpecularGlossyMaterial"
                    model: ["NoLighting", "FragmentLighting"]
                    backendValue: backendValues.lighting
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Albedo")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Color")
                tooltip: qsTr("Sets the albedo color of the material.")
            }

            ColorEditor {
                backendValue: backendValues.albedoColor
                supportGradient: false
            }

            PropertyLabel {
                text: qsTr("Map")
                tooltip: qsTr("Sets a texture used to set the albedo color of the material.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.albedoMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                    + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Use Single Channel")
                tooltip: qsTr("Use only a single channel from albedoMap.")
            }

            SecondColumnLayout {
                CheckBox {
                    id: albedoSingleChannelCheckBox
                    text: checked ? qsTr("Enabled") : qsTr("Disabled")
                    backendValue: backendValues.albedoSingleChannelEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Channel")
                tooltip: qsTr("Sets the texture channel used to read the albedo value from albedoMap.")
            }

            SecondColumnLayout {
                ComboBox {
                    enabled: albedoSingleChannelCheckBox.checked
                    scope: "Material"
                    model: ["R", "G", "B", "A"]
                    backendValue: backendValues.albedoChannel
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Specular")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Color")
                tooltip: qsTr("Sets the specular color of the material.")
            }

            ColorEditor {
                backendValue: backendValues.specularColor
                supportGradient: false
            }

            PropertyLabel {
                text: qsTr("Map")
                tooltip: qsTr("Sets a texture used to set the specular color of the material.")
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
                text: qsTr("Use Single Channel")
                tooltip: qsTr("Use only a single channel from specularMap.")
            }

            SecondColumnLayout {
                CheckBox {
                    id: specularSingleChannelCheckBox
                    text: checked ? qsTr("Enabled") : qsTr("Disabled")
                    backendValue: backendValues.specularSingleChannelEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Channel")
                tooltip: qsTr("Sets the texture channel used to read the specular value from specularMap.")
            }

            SecondColumnLayout {
                ComboBox {
                    enabled: specularSingleChannelCheckBox.checked
                    scope: "Material"
                    model: ["R", "G", "B", "A"]
                    backendValue: backendValues.specularChannel
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Glossiness")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Amount")
                tooltip: qsTr("Sets the size of the specular highlight generated from lights, and the clarity of reflections in general.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.glossiness
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Map")
                tooltip: qsTr("Sets a texture to control the glossiness of the material.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.glossinessMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Channel")
                tooltip: qsTr("Sets the texture channel used to read the glossiness value from glossinessMap.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "Material"
                    model: ["R", "G", "B", "A"]
                    backendValue: backendValues.glossinessChannel
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Normal")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Map")
                tooltip: qsTr("Sets an RGB image used to simulate fine geometry displacement across the surface of the material.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.normalMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Strength")
                tooltip: qsTr("Sets the amount of simulated displacement for the normalMap.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.normalStrength
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Occlusion")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Amount")
                tooltip: qsTr("Sets the factor used to modify the values from the occlusionMap texture.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.occlusionAmount
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Map")
                tooltip: qsTr("Sets a texture used to determine how much indirect light the different areas of the material should receive.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.occlusionMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Channel")
                tooltip: qsTr("Sets the texture channel used to read the occlusion value from occlusionMap.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "Material"
                    model: ["R", "G", "B", "A"]
                    backendValue: backendValues.occlusionChannel
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
                    sliderIndicatorVisible: true
                    backendValue: backendValues.opacity
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Map")
                tooltip: qsTr("Sets a texture used to control the opacity differently for different parts of the material.")
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
                tooltip: qsTr("Sets the texture channel used to read the opacity value from opacityMap.")
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

            PropertyLabel {
                text: qsTr("Invert Channel")
                tooltip: qsTr("Invert the values of the opacity map.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: checked ? qsTr("Enabled") : qsTr("Disabled")
                    backendValue: backendValues.invertOpacityMapValue
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Emissive Color")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Map")
                tooltip: qsTr("Sets a texture to be used to set the emissive factor for different parts of the material.")
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

            PropertyLabel {
                text: qsTr("Factor")
                tooltip: qsTr("Sets the color of self-illumination for this material.")
            }

            SecondColumnLayout {
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                    + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: 0
                    maximumValue: 16
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.emissiveFactor_x
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "R"
                    color: StudioTheme.Values.theme3DAxisXColor
                }

                ExpandingSpacer {}
            }

            PropertyLabel {}

            SecondColumnLayout {
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                    + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: 0
                    maximumValue: 16
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.emissiveFactor_y
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "G"
                    color: StudioTheme.Values.theme3DAxisYColor
                }

                ExpandingSpacer {}
            }

            PropertyLabel {}

            SecondColumnLayout {
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                    + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: 0
                    maximumValue: 16
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.emissiveFactor_z
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "B"
                    color: StudioTheme.Values.theme3DAxisZColor
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Use Single Channel")
                tooltip: qsTr("Use only a single channel from emissiveMap.")
            }

            SecondColumnLayout {
                CheckBox {
                    id: emissiveSingleChannelCheckBox
                    text: checked ? qsTr("Enabled") : qsTr("Disabled")
                    backendValue: backendValues.emissiveSingleChannelEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Channel")
                tooltip: qsTr("Sets the texture channel used to read the emissive value from emissiveMap.")
            }

            SecondColumnLayout {
                ComboBox {
                    enabled: emissiveSingleChannelCheckBox.checked
                    scope: "Material"
                    model: ["R", "G", "B", "A"]
                    backendValue: backendValues.emissiveChannel
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Height")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Amount")
                tooltip: qsTr("Sets the factor used to modify the values from the heightMap texture.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.heightAmount
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Map")
                tooltip: qsTr("Sets a texture used to determine the height the texture will be displaced when rendered through the use of Parallax Mapping.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.heightMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Channel")
                tooltip: qsTr("Sets the texture channel used to read the height value from heightMap.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "Material"
                    model: ["R", "G", "B", "A"]
                    backendValue: backendValues.heightChannel
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Min Map Samples")
                tooltip: qsTr("Sets the minimum number of samples used for performing Parallax Occlusion Mapping using the heightMap.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 1
                    maximumValue: 128
                    decimals: 0
                    sliderIndicatorVisible: true
                    backendValue: backendValues.minHeightMapSamples
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Max Map Samples")
                tooltip: qsTr("Sets the maximum number of samples used for performing Parallax Occlusion Mapping using the heightMap.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 1
                    maximumValue: 256
                    decimals: 0
                    sliderIndicatorVisible: true
                    backendValue: backendValues.maxHeightMapSamples
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Clearcoat")
        width: parent.width

        SectionLayout {

            PropertyLabel {
                text: qsTr("Amount")
                tooltip: qsTr("Sets the intensity of the clearcoat layer.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.clearcoatAmount
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Map")
                tooltip: qsTr("Sets a texture used to determine the intensity of the clearcoat layer.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.clearcoatMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Channel")
                tooltip: qsTr("Sets the texture channel used to read the intensity from clearcoatMap.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "Material"
                    model: ["R", "G", "B", "A"]
                    backendValue: backendValues.clearcoatChannel
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Roughness Amount")
                tooltip: qsTr("Sets the roughness of the clearcoat layer.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.clearcoatRoughnessAmount
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Roughness Map")
                tooltip: qsTr("Sets a texture used to determine the roughness of the clearcoat layer.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.clearcoatRoughnessMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Roughness Channel")
                tooltip: qsTr("Sets the texture channel used to read the roughness from clearcoatRoughnessMap.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "Material"
                    model: ["R", "G", "B", "A"]
                    backendValue: backendValues.clearcoatRoughnessChannel
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Normal Map")
                tooltip: qsTr("Sets a texture used as a normalMap for the clearcoat layer.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.clearcoatNormalMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Normal Strength")
                tooltip: qsTr("Sets the Normal Strength of the clearcoat layer.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.clearcoatNormalStrength
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Fresnel Power")
                tooltip: qsTr("Sets the fresnel power.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1000
                    stepSize: 0.1
                    decimals: 2

                    backendValue: backendValues.clearcoatFresnelPower
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Enable scale and bias")
                tooltip: qsTr("Sets whether fresnel scale and bias are enabled.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: checked ? qsTr("Enabled") : qsTr("Disabled")
                    backendValue: backendValues.clearcoatFresnelScaleBiasEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Fresnel Scale")
                tooltip: qsTr("Sets the fresnel scale.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 5
                    stepSize: 0.1
                    decimals: 2

                    backendValue: backendValues.clearcoatFresnelScale
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Fresnel Bias")
                tooltip: qsTr("Sets the fresnel bias.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -1
                    maximumValue: 1
                    stepSize: 0.1
                    decimals: 2

                    backendValue: backendValues.clearcoatFresnelBias
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Refraction")
        width: parent.width

        SectionLayout {

            PropertyLabel {
                text: qsTr("Transmission Factor")
                tooltip: qsTr("Sets the base percentage of light that is transmitted through the surface.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.transmissionFactor
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Transmission Map")
                tooltip: qsTr("Sets a texture that contains the transmission percentage of a the surface.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.transmissionMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Transmission Channel")
                tooltip: qsTr("Sets the texture channel used to read the transmission percentage from transmissionMap.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "Material"
                    model: ["R", "G", "B", "A"]
                    backendValue: backendValues.transmissionChannel
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Thickness Factor")
                tooltip: qsTr("Sets the thickness of the volume beneath the surface in model coordinate space.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: Infinity
                    decimals: 2
                    backendValue: backendValues.thicknessFactor
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Thickness Map")
                tooltip: qsTr("Sets a texture that contains the thickness of a the material volume.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.thicknessMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Thickness Channel")
                tooltip: qsTr("Sets the texture channel used to read the thickness amount from thicknessMap.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "Material"
                    model: ["R", "G", "B", "A"]
                    backendValue: backendValues.thicknessChannel
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Attenuation Color")
                tooltip: qsTr("Sets the color that white lights turn into due to absorption when reaching the attenuation distance.")
            }

            ColorEditor {
                backendValue: backendValues.attenuationColor
                supportGradient: false
            }

            PropertyLabel {
                text: qsTr("Attenuation Distance")
                tooltip: qsTr("Sets the average distance in world space that light travels in the medium before interacting with a particle.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: Infinity
                    decimals: 2
                    backendValue: backendValues.attenuationDistance
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Fresnel")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Fresnel Power")
                tooltip: qsTr("Sets the fresnel power.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1000
                    stepSize: 0.1
                    decimals: 2

                    backendValue: backendValues.fresnelPower
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Enable scale and bias")
                tooltip: qsTr("Sets whether fresnel scale and bias are enabled.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: checked ? qsTr("Enabled") : qsTr("Disabled")
                    backendValue: backendValues.fresnelScaleBiasEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Fresnel Scale")
                tooltip: qsTr("Sets the fresnel scale.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 5
                    stepSize: 0.1
                    decimals: 2

                    backendValue: backendValues.fresnelScale
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Fresnel Bias")
                tooltip: qsTr("Sets the fresnel bias.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -1
                    maximumValue: 1
                    stepSize: 0.1
                    decimals: 2

                    backendValue: backendValues.fresnelBias
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Vertex Color")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Show Colors")
                tooltip: qsTr("Sets whether vertex colors are used to modulate the base color.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: checked ? qsTr("Enabled") : qsTr("Disabled")
                    backendValue: backendValues.vertexColorsEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Enable Masks")
                tooltip: qsTr("Sets whether vertex colors mask are used.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: checked ? qsTr("Enabled") : qsTr("Disabled")
                    backendValue: backendValues.vertexColorsMaskEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            ListModel {
                id: colorMaskModel

                ListElement {
                    name: "Glossiness"
                    flag: "GlossinessMask"
                }
                ListElement {
                    name: "Normal Strength"
                    flag: "NormalStrengthMask"
                }
                ListElement {
                    name: "Clearcoat Amount"
                    flag: "ClearcoatAmountMask"
                }
                ListElement {
                    name: "Clearcoat Roughness Amount"
                    flag: "ClearcoatRoughnessAmountMask"
                }
                ListElement {
                    name: "Clearcoat Normal Strength"
                    flag: "ClearcoatNormalStrengthMask"
                }
                ListElement {
                    name: "Height Amount"
                    flag: "HeightAmountMask"
                }
                ListElement {
                    name: "Occlusion Amount"
                    flag: "OcclusionAmountMask"
                }
                ListElement {
                    name: "Thickness Factor"
                    flag: "ThicknessFactorMask"
                }
                ListElement {
                    name: "Transmission Factor"
                    flag: "TransmissionFactorMask"
                }
            }

            PropertyLabel {
                text: qsTr("Mask R")
                tooltip: qsTr("Sets the properties masked by the vertex color red channel.")
            }

            SecondColumnLayout {
                FlagsComboBox {
                    backendValue: backendValues.vertexColorRedMask
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth

                    itemsModel: colorMaskModel
                    scope: "SpecularGlossyMaterial"
                    zeroFlag: "NoMask"
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Mask G")
                tooltip: qsTr("Sets the properties masked by the vertex color green channel.")
            }

            SecondColumnLayout {
                FlagsComboBox {
                    backendValue: backendValues.vertexColorGreenMask
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth

                    itemsModel: colorMaskModel
                    scope: "SpecularGlossyMaterial"
                    zeroFlag: "NoMask"
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Mask B")
                tooltip: qsTr("Sets the properties masked by the vertex color blue channel.")
            }

            SecondColumnLayout {
                FlagsComboBox {
                    backendValue: backendValues.vertexColorBlueMask
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth

                    itemsModel: colorMaskModel
                    scope: "SpecularGlossyMaterial"
                    zeroFlag: "NoMask"
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Mask A")
                tooltip: qsTr("Sets the properties masked by the vertex color alpha channel.")
            }

            SecondColumnLayout {
                FlagsComboBox {
                    backendValue: backendValues.vertexColorAlphaMask
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth

                    itemsModel: colorMaskModel
                    scope: "SpecularGlossyMaterial"
                    zeroFlag: "NoMask"
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Advanced")
        width: parent.width

        SectionLayout {

            PropertyLabel {
                text: qsTr("Point Size")
                tooltip: qsTr("Sets the size of the points rendered, when the geometry is using a primitive type of points.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1024
                    decimals: 0
                    backendValue: backendValues.pointSize
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Line Width")
                tooltip: qsTr("Sets the width of the lines rendered, when the geometry is using a primitive type of lines or line strips.")
            }
            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1024
                    decimals: 0
                    backendValue: backendValues.lineWidth
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }
}
