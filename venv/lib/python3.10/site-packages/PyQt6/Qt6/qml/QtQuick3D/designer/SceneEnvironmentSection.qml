// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Column {
    width: parent.width

    Section {
        width: parent.width
        caption: qsTr("Scene Environment")

        SectionLayout {
            id: baseSectionLayout
            property bool isColorMode: backgroundModeComboBox.currentIndex === 2
            property bool isSkyBoxMode: backgroundModeComboBox.currentIndex === 3
            property bool isSkyBoxCubeMapMode: backgroundModeComboBox.currentIndex === 4

            PropertyLabel {
                text: qsTr("Background Mode")
                tooltip: qsTr("Sets if and how the background of the scene should be cleared.")
            }

            SecondColumnLayout {
                ComboBox {
                    id: backgroundModeComboBox
                    scope: "SceneEnvironment"
                    model: ["Transparent", "Unspecified", "Color", "SkyBox", "SkyBoxCubeMap"]
                    backendValue: backendValues.backgroundMode
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: baseSectionLayout.isColorMode
                text: qsTr("Clear Color")
                tooltip: qsTr("Sets which color will be used to clear the viewport when using SceneEnvironment.Color for the backgroundMode property.")
            }

            ColorEditor {
                visible: baseSectionLayout.isColorMode
                backendValue: backendValues.clearColor
                supportGradient: false
            }

            PropertyLabel {
                visible: baseSectionLayout.isSkyBoxCubeMapMode
                text: qsTr("Skybox Cube Map")
                tooltip: qsTr("Sets a cubemap to be used as a skybox when the background mode is SkyBoxCubeMap.")
            }

            SecondColumnLayout {
                visible: baseSectionLayout.isSkyBoxCubeMapMode
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.CubeMapTexture"
                    backendValue: backendValues.skyBoxCubeMap
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: baseSectionLayout.isSkyBoxMode || baseSectionLayout.isSkyBoxCubeMapMode
                text: qsTr("Skybox Blur")
                tooltip: qsTr("Sets how much to blur the skybox when using SceneEnvironment.SkyBox for the backgroundMode property.")
            }

            SecondColumnLayout {
                visible: baseSectionLayout.isSkyBoxMode || baseSectionLayout.isSkyBoxCubeMapMode
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.skyboxBlurAmount
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Effects")
                tooltip: qsTr("Post Processing effects applied to this scene.")
                Layout.alignment: Qt.AlignTop
                Layout.topMargin: 5
            }

            SecondColumnLayout {
                EditableListView {
                    backendValue: backendValues.effects
                    model: backendValues.effects.expressionAsList
                    Layout.fillWidth: true
                    typeFilter: "QtQuick3D.Effect"

                    onAdd: function(value) { backendValues.effects.idListAdd(value) }
                    onRemove: function(idx) { backendValues.effects.idListRemove(idx) }
                    onReplace: function (idx, value) { backendValues.effects.idListReplace(idx, value) }
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Tonemap Mode")
                tooltip: qsTr("Sets how colors are tonemapped before rendering.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "SceneEnvironment"
                    model: ["TonemapModeNone", "TonemapModeLinear", "TonemapModeAces", "TonemapModeHejlDawson", "TonemapModeFilmic"]
                    backendValue: backendValues.tonemapMode
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Fog")
                tooltip: qsTr("Settings for Fog applied to the scene.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Fog"
                    backendValue: backendValues.fog
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

        }
    }

    Section {
        id: antialiasingSection
        width: parent.width
        caption: qsTr("Antialiasing")

        property bool isAntialiasingEnabled: antialiasingModeComboBox.currentIndex !== 0

        SectionLayout {
            PropertyLabel {
                text: qsTr("Antialiasing Mode")
                tooltip: qsTr("Sets the antialiasing mode applied to the scene.")
            }

            SecondColumnLayout {
                ComboBox {
                    id: antialiasingModeComboBox
                    scope: "SceneEnvironment"
                    model: ["NoAA", "SSAA", "MSAA", "ProgressiveAA"]
                    backendValue: backendValues.antialiasingMode
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: antialiasingSection.isAntialiasingEnabled
                text: qsTr("Antialiasing Quality")
                tooltip: qsTr("Sets the level of antialiasing applied to the scene.")
            }

            SecondColumnLayout {
                visible: antialiasingSection.isAntialiasingEnabled
                ComboBox {
                    scope: "SceneEnvironment"
                    model: ["Medium", "High", "VeryHigh"]
                    backendValue: backendValues.antialiasingQuality
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Specular AA")
                tooltip: qsTr("Enables specular antialiasing.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.specularAAEnabled.valueToString
                    backendValue: backendValues.specularAAEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Temporal AA")
                tooltip: qsTr("Enables temporal antialiasing using camera jittering and frame blending.")
            }

            SecondColumnLayout {
                CheckBox {
                    id: temporalAAEnabledCheckBox
                    text: backendValues.temporalAAEnabled.valueToString
                    backendValue: backendValues.temporalAAEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: temporalAAEnabledCheckBox.checked
                text: qsTr("Temporal AA Strength")
                tooltip: qsTr("Sets the amount of temporal antialiasing applied.")
            }

            SecondColumnLayout {
                visible: temporalAAEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0.01
                    maximumValue: 2.0
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.temporalAAStrength
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        width: parent.width
        caption: qsTr("Ambient Occlusion")

        SectionLayout {

            PropertyLabel {
                text: qsTr("Enabled")
                tooltip: qsTr("Enables ambient occlusion.")
            }

            SecondColumnLayout {
                CheckBox {
                    id: ambientOcclusionEnabledCheckBox
                    text: backendValues.aoEnabled.valueToString
                    backendValue: backendValues.aoEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }


            PropertyLabel {
                visible: ambientOcclusionEnabledCheckBox.checked
                text: qsTr("Strength")
                tooltip: qsTr("Sets the amount of ambient occulusion applied.")
            }

            SecondColumnLayout {
                visible: ambientOcclusionEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 100
                    sliderIndicatorVisible: true
                    decimals: 0
                    backendValue: backendValues.aoStrength
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: ambientOcclusionEnabledCheckBox.checked
                text: qsTr("Distance")
                tooltip: qsTr("Sets roughly how far ambient occlusion shadows spread away from objects.")
            }

            SecondColumnLayout {
                visible: ambientOcclusionEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.aoDistance
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: ambientOcclusionEnabledCheckBox.checked
                text: qsTr("Softness")
                tooltip: qsTr("Sets how smooth the edges of the ambient occlusion shading are.")
            }

            SecondColumnLayout {
                visible: ambientOcclusionEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 50
                    sliderIndicatorVisible: true
                    decimals: 2
                    backendValue: backendValues.aoSoftness
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: ambientOcclusionEnabledCheckBox.checked
                text: qsTr("Sample Rate")
                tooltip: qsTr("Sets ambient occlusion quality (more shades of gray) at the expense of performance.")
            }

            SecondColumnLayout {
                visible: ambientOcclusionEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 2
                    maximumValue: 4
                    decimals: 0
                    stepSize: 1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.aoSampleRate
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: ambientOcclusionEnabledCheckBox.checked
                text: qsTr("Bias")
                tooltip: qsTr("Sets a cutoff distance preventing objects from exhibiting ambient occlusion at close distances.")
            }

            SecondColumnLayout {
                visible: ambientOcclusionEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.aoBias
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: ambientOcclusionEnabledCheckBox.checked
                text: qsTr("Dither")
                tooltip: qsTr("Enables scattering the edges of the ambient occlusion shadow bands to improve smoothness.")
            }

            SecondColumnLayout {
                visible: ambientOcclusionEnabledCheckBox.checked
                CheckBox {
                    id: aoDitherCheckBox
                    text: backendValues.aoDither.valueToString
                    backendValue: backendValues.aoDither
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        width: parent.width
        caption: qsTr("Image Based Lighting")

        SectionLayout {
            PropertyLabel {
                text: qsTr("HDR Image")
                tooltip: qsTr("Sets an image to use to light the scene, either instead of, or in addition to standard lights.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.lightProbe
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Exposure")
                tooltip: qsTr("Sets the amount of light emitted by the light probe.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.probeExposure
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Horizon")
                tooltip: qsTr("Sets the light probe horizon. When set, adds darkness (black) to the bottom of the environment, forcing the lighting to come predominantly from the top of the image.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.probeHorizon
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Orientation")
                tooltip: qsTr("Sets the orientation of the light probe.")
            }

            SecondColumnLayout {
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.probeOrientation_x
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "X"
                    color: StudioTheme.Values.theme3DAxisXColor
                }

                ExpandingSpacer {}
            }

            PropertyLabel {}

            SecondColumnLayout {
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.probeOrientation_y
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "Y"
                    color: StudioTheme.Values.theme3DAxisYColor
                }

                ExpandingSpacer {}
            }

            PropertyLabel {}

            SecondColumnLayout {
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.probeOrientation_z
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "Z"
                    color: StudioTheme.Values.theme3DAxisZColor
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        width: parent.width
        caption: qsTr("Advanced")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Enable Depth Test")
                tooltip: qsTr("Enables depth testing. Disable to optimize render speed for layers with mostly transparent objects.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.depthTestEnabled.valueToString
                    backendValue: backendValues.depthTestEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Enable Depth Prepass")
                tooltip: qsTr("Enables draw depth buffer as a separate pass. Disable to optimize render speed for layers with low depth complexity.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.depthPrePassEnabled.valueToString
                    backendValue: backendValues.depthPrePassEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Debug Settings")
                tooltip: qsTr("Additional render settings for debugging scenes.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.DebugSettings"
                    backendValue: backendValues.debugSettings
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Light Mapper")
                tooltip: qsTr("Sets the light mapper object for the scene.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Lightmapper"
                    backendValue: backendValues.lightmapper
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            // ### This is not yet implemented in the DS backend since rect does not have
            // a way to access x, y, width, or height via the _ notation.
            // PropertyLabel {
            //     text: qsTr("Scissor Rect")
            //     tooltip: qsTr("Defines a scissor rectangle in view coordinates.")
            // }

            // SecondColumnLayout {
            //     SpinBox {
            //         maximumValue: 999999
            //         minimumValue: -999999
            //         decimals: 0
            //         stepSize: 1
            //         backendValue: backendValues.scissorRect_x
            //         implicitWidth: StudioTheme.Values.twoControlColumnWidth
            //                     + StudioTheme.Values.actionIndicatorWidth
            //     }

            //     Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            //     ControlLabel {
            //         text: "X"
            //         tooltip: qsTr("Sets the scissor clip X offset from left to right.")
            //     }

            //     Spacer { implicitWidth: StudioTheme.Values.controlGap }

            //     SpinBox {
            //         maximumValue: 999999
            //         minimumValue: -999999
            //         decimals: 0
            //         stepSize: 1
            //         backendValue: backendValues.scissorRect_y
            //         implicitWidth: StudioTheme.Values.twoControlColumnWidth
            //                     + StudioTheme.Values.actionIndicatorWidth
            //     }

            //     Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            //     ControlLabel {
            //         text: "Y"
            //         tooltip: qsTr("Sets the scissor clip Y offset from bottom to top.")
            //     }

            //     ExpandingSpacer {}
            // }

            // PropertyLabel {} // spacer

            // SecondColumnLayout {
            //     SpinBox {
            //         maximumValue: 999999
            //         minimumValue: -999999
            //         decimals: 0
            //         stepSize: 1
            //         backendValue: backendValues.scissorRect_width
            //         implicitWidth: StudioTheme.Values.twoControlColumnWidth
            //                     + StudioTheme.Values.actionIndicatorWidth
            //     }

            //     Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            //     ControlLabel {
            //         text: "W"
            //         tooltip: qsTr("Sets the scissor clip width")
            //     }

            //     Spacer { implicitWidth: StudioTheme.Values.controlGap }

            //     SpinBox {
            //         maximumValue: 999999
            //         minimumValue: -999999
            //         decimals: 0
            //         stepSize: 1
            //         backendValue: backendValues.scissorRect_height
            //         implicitWidth: StudioTheme.Values.twoControlColumnWidth
            //                     + StudioTheme.Values.actionIndicatorWidth
            //     }

            //     Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            //     ControlLabel {
            //         text: "H"
            //         tooltip: qsTr("Sets the scissor clip height")
            //     }

            //     ExpandingSpacer {}
            // }
        }
    }
}
