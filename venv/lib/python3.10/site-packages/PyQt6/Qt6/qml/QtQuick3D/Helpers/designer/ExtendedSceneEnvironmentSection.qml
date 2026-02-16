// Copyright (C) 2023 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Column {
    width: parent.width

    Section {
        width: parent.width
        caption: qsTr("Extended Scene Environment")

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
                text: qsTr("FXAA")
                tooltip: qsTr("Enables fast approximate antialiasing.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.fxaaEnabled.valueToString
                    backendValue: backendValues.fxaaEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
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
        caption: qsTr("Tone Mapping")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Mode")
                tooltip: qsTr("Sets how colors are tonemapped from HDR to LDR before being displayed.")
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
                text: qsTr("Exposure")
                tooltip: qsTr("Sets the exposure of the scene.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 10
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.exposure
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("White Point")
                tooltip: qsTr("Sets the white point of the scene.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.whitePoint
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Sharpening")
                tooltip: qsTr("Set the sharpening amount applied to the scene.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.sharpnessAmount
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Dithering")
                tooltip: qsTr("Enables dithering to reduce banding artifacts.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.ditheringEnabled.valueToString
                    backendValue: backendValues.ditheringEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

        }
    }

    Section {
        width: parent.width
        caption: qsTr("Color Adjustments")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Enabled")
                tooltip: qsTr("Enables color adjustments")
            }

            SecondColumnLayout {
                CheckBox {
                    id: adjustmentsEnabledCheckBox
                    text: backendValues.colorAdjustmentsEnabled.valueToString
                    backendValue: backendValues.colorAdjustmentsEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: adjustmentsEnabledCheckBox.checked
                text: qsTr("Brightness")
                tooltip: qsTr("Adjusts the brightness of the scene.")
            }

            SecondColumnLayout {
                visible: adjustmentsEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0.01
                    maximumValue: 8.0
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.adjustmentBrightness
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: adjustmentsEnabledCheckBox.checked
                text: qsTr("Contrast")
                tooltip: qsTr("Adjusts the contrast of the scene.")
            }

            SecondColumnLayout {
                visible: adjustmentsEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0.01
                    maximumValue: 8.0
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.adjustmentContrast
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: adjustmentsEnabledCheckBox.checked
                text: qsTr("Saturation")
                tooltip: qsTr("Adjusts the saturation of the scene.")
            }

            SecondColumnLayout {
                visible: adjustmentsEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0.01
                    maximumValue: 8.0
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.adjustmentSaturation
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        width: parent.width
        caption: qsTr("Color Grading")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Enabled")
                tooltip: qsTr("Enables color grading via look up table (LUT) textures.")
            }

            SecondColumnLayout {
                CheckBox {
                    id: colorGradingEnabledCheckBox
                    text: backendValues.lutEnabled.valueToString
                    backendValue: backendValues.lutEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: colorGradingEnabledCheckBox.checked
                text: qsTr("Size")
                tooltip: qsTr("Sets the size of the LUT texture. The texture should have the dimensions: width=(size * size), height=(size).")
            }

            SecondColumnLayout {
                visible: colorGradingEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 1
                    maximumValue: 64
                    decimals: 0
                    stepSize: 1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.skyboxBlurAmount
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: colorGradingEnabledCheckBox.checked
                text: qsTr("Texture")
                tooltip: qsTr("Sets the source of the LUT texture.")
            }

            SecondColumnLayout {
                visible: colorGradingEnabledCheckBox.checked
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.lutTexture
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: colorGradingEnabledCheckBox.checked
                text: qsTr("Alpha Mix")
                tooltip: qsTr("Sets the amount of color grading to mix with the scene.")
            }

            SecondColumnLayout {
                visible: colorGradingEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    sliderIndicatorVisible: true
                    decimals: 2
                    stepSize: 0.01
                    backendValue: backendValues.lutFilterAlpha
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

        }
    }

    Section {
        width: parent.width
        caption: qsTr("Ambient Occlusion (SSAO)")

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
                    minimumValue: -1.0
                    maximumValue: 1.0
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
        caption: qsTr("Depth of Field")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Enabled")
                tooltip: qsTr("Enables Depth of Field effect.")
            }

            SecondColumnLayout {
                CheckBox {
                    id: depthOfFieldEnabledCheckBox
                    text: backendValues.depthOfFieldEnabled.valueToString
                    backendValue: backendValues.depthOfFieldEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: depthOfFieldEnabledCheckBox.checked
                text: qsTr("Focus Distance")
                tooltip: qsTr("Sets the distance from the camera at which objects are in focus.")
            }

            SecondColumnLayout {
                visible: depthOfFieldEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.depthOfFieldFocusDistance
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: depthOfFieldEnabledCheckBox.checked
                text: qsTr("Focus Range")
                tooltip: qsTr("Sets the range of distances from the focus distance that are in focus.")
            }

            SecondColumnLayout {
                visible: depthOfFieldEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.depthOfFieldFocusRange
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: depthOfFieldEnabledCheckBox.checked
                text: qsTr("Blur Amount")
                tooltip: qsTr("Sets the amount of blur applied to objects outside the focus range.")
            }

            SecondColumnLayout {
                visible: depthOfFieldEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 25
                    decimals: 2
                    stepSize: 0.01
                    backendValue: backendValues.depthOfFieldBlurAmount
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        width: parent.width
        caption: qsTr("Glow")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Enabled")
                tooltip: qsTr("Enables the Glow/Bloom Effect")
            }

            SecondColumnLayout {
                CheckBox {
                    id: glowEnabledCheckBox
                    text: backendValues.glowEnabled.valueToString
                    backendValue: backendValues.glowEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: glowEnabledCheckBox.checked
                text: qsTr("High Quality")
                tooltip: qsTr("Enables high quality mode for the glow effect.")
            }

            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked
                CheckBox {
                    text: backendValues.glowQualityHigh.valueToString
                    backendValue: backendValues.glowQualityHigh
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: glowEnabledCheckBox.checked
                text: qsTr("Bicubic Upsampling")
                tooltip: qsTr("Reduces the aliasing artifacts and boxing in the glow effect.")
            }

            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked
                CheckBox {
                    text: backendValues.glowUseBicubicUpscale.valueToString
                    backendValue: backendValues.glowUseBicubicUpscale
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: glowEnabledCheckBox.checked
                text: qsTr("Strength")
                tooltip: qsTr("Sets the strength of the glow effect.")
            }

            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 2
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.glowStrength
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: glowEnabledCheckBox.checked
                text: qsTr("Intensity")
                tooltip: qsTr("Sets the Intensity of the glow effect.")
            }

            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 2
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.glowIntensity
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: glowEnabledCheckBox.checked
                text: qsTr("Bloom")
                tooltip: qsTr("Sets the amount of bloom applied to the glow effect.")
            }

            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.glowBloom
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: glowEnabledCheckBox.checked
                text: qsTr("Lower Threshold")
                tooltip: qsTr("Sets the minimum brightness of the HDR glow.")
            }

            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 4
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.glowHDRMinimumValue
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: glowEnabledCheckBox.checked
                text: qsTr("Upper Threshold")
                tooltip: qsTr("Sets the maximum brightness of the HDR glow.")
            }

            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 256
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.glowHDRMaximumValue
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: glowEnabledCheckBox.checked
                text: qsTr("HDR Scale")
                tooltip: qsTr("Sets the bleed scale of the HDR glow.")
            }

            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 8
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.glowHDRScale
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: glowEnabledCheckBox.checked
                text: qsTr("Blend Mode")
                tooltip: qsTr("Sets the blending mode for the glow effect.")
            }

            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked
                ComboBox {
                    scope: "ExtendedSceneEnvironment.GlowBlendMode"
                    model: ["Additive", "Screen", "SoftLight", "Replace"]
                    backendValue: backendValues.glowBlendMode
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: glowEnabledCheckBox.checked
                text: qsTr("Blur Levels")
                tooltip: qsTr("Sets which of the blur passes get applied to the glow effect.")
            }

            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked
                // ### This isn't perfect, but it's the best we can do for now
                ActionIndicator {
                    id: glowLevelController
                    icon.color: extFuncLogic.color
                    icon.text: extFuncLogic.glyph
                    onClicked: extFuncLogic.show()
                    forceVisible: extFuncLogic.menuVisible
                    visible: true

                    property var enableLevel1: { "value": false, "isInModel": false}
                    property var enableLevel2: { "value": false, "isInModel": false}
                    property var enableLevel3: { "value": false, "isInModel": false}
                    property var enableLevel4: { "value": false, "isInModel": false}
                    property var enableLevel5: { "value": false, "isInModel": false}
                    property var enableLevel6: { "value": false, "isInModel": false}
                    property var enableLevel7: { "value": false, "isInModel": false}

                    property variant backendValue: backendValues.glowLevel
                    property variant valueFromBackend: backendValue === undefined ? 0 : backendValue.value
                    property bool blockLevels: false

                    onBackendValueChanged: evaluateLevels()
                    onValueFromBackendChanged: evaluateLevels()

                    Connections {
                        target: modelNodeBackend
                        function onSelectionChanged() {
                            evaluateLevels()
                        }
                    }

                    Component.onCompleted: evaluateLevels()

                    function evaluateLevels() {
                        blockLevels = true
                        enableLevel1 = { "value": valueFromBackend & 1, "isInModel": false}
                        enableLevel2 = { "value": valueFromBackend & 2, "isInModel": false}
                        enableLevel3 = { "value": valueFromBackend & 4, "isInModel": false}
                        enableLevel4 = { "value": valueFromBackend & 8, "isInModel": false}
                        enableLevel5 = { "value": valueFromBackend & 16, "isInModel": false}
                        enableLevel6 = { "value": valueFromBackend & 32, "isInModel": false}
                        enableLevel7 = { "value": valueFromBackend & 64, "isInModel": false}
                        blockLevels = false
                    }

                    function composeExpressionString() {
                        if (blockLevels)
                            return

                        let expressionStr = "";

                        if (enableLevel1.value || enableLevel2.value || enableLevel3.value || enableLevel4.value
                                || enableLevel5.value || enableLevel6.value || enableLevel7.value) {
                            if (enableLevel1.value)
                                expressionStr += " | ExtendedSceneEnvironment.GlowLevel.One";
                            if (enableLevel2.value)
                                expressionStr += " | ExtendedSceneEnvironment.GlowLevel.Two";
                            if (enableLevel3.value)
                                expressionStr += " | ExtendedSceneEnvironment.GlowLevel.Three";
                            if (enableLevel4.value)
                                expressionStr += " | ExtendedSceneEnvironment.GlowLevel.Four";
                            if (enableLevel5.value)
                                expressionStr += " | ExtendedSceneEnvironment.GlowLevel.Five";
                            if (enableLevel6.value)
                                expressionStr += " | ExtendedSceneEnvironment.GlowLevel.Six";
                            if (enableLevel7.value)
                                expressionStr += " | ExtendedSceneEnvironment.GlowLevel.Seven";

                            expressionStr = expressionStr.substring(3);

                            backendValue.expression = expressionStr
                        } else {
                            expressionStr = "0";
                            backendValue.expression = expressionStr
                        }
                    }
                    ExtendedFunctionLogic {
                        id: extFuncLogic
                        backendValue: backendValues.glowLevel
                        onReseted: {
                            glowLevelController.enableLevel1 = { "value": true, "isInModel": false}
                            glowLevelController.enableLevel2 = { "value": false, "isInModel": false}
                            glowLevelController.enableLevel3 = { "value": false, "isInModel": false}
                            glowLevelController.enableLevel4 = { "value": false, "isInModel": false}
                            glowLevelController.enableLevel5 = { "value": false, "isInModel": false}
                            glowLevelController.enableLevel6 = { "value": false, "isInModel": false}
                            glowLevelController.enableLevel7 = { "value": false, "isInModel": false}
                            glowLevelController.evaluateLevels()
                        }
                    }
                }
            }

            PropertyLabel {
                // spacer
                visible: glowEnabledCheckBox.checked
            }

            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked

                Item {
                    // spacer for the always hiden action indicator
                    width: StudioTheme.Values.actionIndicatorWidth
                }

                CheckBox {
                    text: qsTr("Level 1")
                    backendValue: glowLevelController.enableLevel1
                    actionIndicatorVisible: false
                    onCheckedChanged: glowLevelController.composeExpressionString()
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                // spacer
                visible: glowEnabledCheckBox.checked
            }
            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked

                Item {
                    // spacer for the always hiden action indicator
                    width: StudioTheme.Values.actionIndicatorWidth
                }

                CheckBox {
                    text: qsTr("Level 2")
                    backendValue: glowLevelController.enableLevel2
                    actionIndicatorVisible: false
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                    onCheckedChanged: glowLevelController.composeExpressionString()
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                // spacer
                visible: glowEnabledCheckBox.checked
            }
            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked

                Item {
                    // spacer for the always hiden action indicator
                    width: StudioTheme.Values.actionIndicatorWidth
                }

                CheckBox {
                    text: qsTr("Level 3")
                    backendValue: glowLevelController.enableLevel3
                    actionIndicatorVisible: false
                    onCheckedChanged: glowLevelController.composeExpressionString()
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                // spacer
                visible: glowEnabledCheckBox.checked
            }
            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked

                Item {
                    // spacer for the always hiden action indicator
                    width: StudioTheme.Values.actionIndicatorWidth
                }

                CheckBox {
                    text: qsTr("Level 4")
                    backendValue: glowLevelController.enableLevel4
                    actionIndicatorVisible: false
                    onCheckedChanged: glowLevelController.composeExpressionString()
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                // spacer
                visible: glowEnabledCheckBox.checked
            }
            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked

                Item {
                    // spacer for the always hiden action indicator
                    width: StudioTheme.Values.actionIndicatorWidth
                }

                CheckBox {
                    text: qsTr("Level 5")
                    backendValue: glowLevelController.enableLevel5
                    actionIndicatorVisible: false
                    onCheckedChanged: glowLevelController.composeExpressionString()
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                // spacer
                visible: glowEnabledCheckBox.checked
            }
            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked

                Item {
                    // spacer for the always hiden action indicator
                    width: StudioTheme.Values.actionIndicatorWidth
                }

                CheckBox {
                    text: qsTr("Level 6")
                    backendValue: glowLevelController.enableLevel6
                    actionIndicatorVisible: false
                    onCheckedChanged: glowLevelController.composeExpressionString()
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
            PropertyLabel {
                // spacer
                visible: glowEnabledCheckBox.checked
            }
            SecondColumnLayout {
                visible: glowEnabledCheckBox.checked

                Item {
                    // spacer for the always hiden action indicator
                    width: StudioTheme.Values.actionIndicatorWidth
                }

                CheckBox {
                    text: qsTr("Level 7")
                    backendValue: glowLevelController.enableLevel7
                    actionIndicatorVisible: false
                    onCheckedChanged: glowLevelController.composeExpressionString()
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

        }
    }

    Section {
        width: parent.width
        caption: qsTr("Vignette")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Enabled")
                tooltip: qsTr("Enables the vignette effect.")
            }

            SecondColumnLayout {
                CheckBox {
                    id: vignetteEnabledCheckBox
                    text: backendValues.vignetteEnabled.valueToString
                    backendValue: backendValues.vignetteEnabled
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: vignetteEnabledCheckBox.checked
                text: qsTr("Color")
                tooltip: qsTr("Sets the color of the vignette effect.")
            }

            ColorEditor {
                visible: vignetteEnabledCheckBox.checked
                backendValue: backendValues.vignetteColor
                supportGradient: false
            }

            PropertyLabel {
                visible: vignetteEnabledCheckBox.checked
                text: qsTr("Strength")
                tooltip: qsTr("Sets the strength of the vignette effect.")
            }

            SecondColumnLayout {
                visible: vignetteEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0.01
                    maximumValue: 15
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.vignetteStrength
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: vignetteEnabledCheckBox.checked
                text: qsTr("Radius")
                tooltip: qsTr("Sets the radius of the vignette effect.")
            }

            SecondColumnLayout {
                visible: vignetteEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 5
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.vignetteRadius
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        width: parent.width
        caption: qsTr("Lens Flare")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Enabled")
                tooltip: qsTr("Enables the Lens Flare effect.")
            }

            SecondColumnLayout {
                CheckBox {
                    id: lensFlareEnabledCheckBox
                    text: backendValues.lensFlareEnabled.valueToString
                    backendValue: backendValues.lensFlareEnabled
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked
                text: qsTr("Bloom Scale")
                tooltip: qsTr("Sets the scale of the lens flare bloom effect.")
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 20
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.lensFlareBloomScale
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked
                text: qsTr("Bloom Bias")
                tooltip: qsTr("Sets the level at which the lens flare bloom starts.")
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 10
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.lensFlareBloomBias
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked
                text: qsTr("Ghost Dispersal")
                tooltip: qsTr("Sets the distance between the lens flare ghosts.")
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0.001
                    maximumValue: 1
                    decimals: 3
                    stepSize: 0.001
                    sliderIndicatorVisible: true
                    backendValue: backendValues.lensFlareGhostDispersal
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked
                text: qsTr("Ghost Count")
                tooltip: qsTr("Sets the amount of lens flare ghosts.")
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 20
                    decimals: 0
                    stepSize: 1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.lensFlareGhostCount
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked
                text: qsTr("Halo Width")
                tooltip: qsTr("Sets the size of the lens flare halo.")
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 3
                    stepSize: 0.001
                    sliderIndicatorVisible: true
                    backendValue: backendValues.lensFlareHaloWidth
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked
                text: qsTr("Stretch Aspect")
                tooltip: qsTr("Set correction factor for roundness of the lens flare halo.")
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 3
                    stepSize: 0.001
                    sliderIndicatorVisible: true
                    backendValue: backendValues.lensFlareStretchToAspect
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked
                text: qsTr("Distortion")
                tooltip: qsTr("Set amount of chromatic aberration in the lens flare.")
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 25
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.lensFlareDistortion
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked
                text: qsTr("Blur")
                tooltip: qsTr("Set amount of blur to apply to the lens flare.")
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked
                SpinBox {
                    minimumValue: 0
                    maximumValue: 50
                    decimals: 2
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.lensFlareBlurAmount
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked
                text: qsTr("Lens Color Texture")
                tooltip: qsTr("A gradient image used for the lens flare lens color.")
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.lensFlareLensColorTexture
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked
                text: qsTr("Apply Dirt")
                tooltip: qsTr("Set whether to apply a dirt texture to the lens flare.")
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked
                CheckBox {
                    id: lensFlareDirtEnabledCheckBox
                    text: backendValues.lensFlareApplyDirtTexture.valueToString
                    backendValue: backendValues.lensFlareApplyDirtTexture
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked && lensFlareDirtEnabledCheckBox.checked
                text: qsTr("Dirt Texture")
                tooltip: qsTr("An image that is used to simulate inperfections on the lens.")
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked && lensFlareDirtEnabledCheckBox.checked
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.lensFlareLensDirtTexture
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked
                text: qsTr("Apply Starburst")
                tooltip: qsTr("Set whether to apply a starburst texture to the lens flare.")
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked
                CheckBox {
                    id: lensFlareStarburstEnabledCheckBox
                    text: backendValues.lensFlareApplyStarburstTexture.valueToString
                    backendValue: backendValues.lensFlareApplyStarburstTexture
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked && lensFlareStarburstEnabledCheckBox.checked
                text: qsTr("Starburst Texture")
                tooltip: qsTr("A noise image to augment the starburst effect of the lens flare.")
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked && lensFlareStarburstEnabledCheckBox.checked
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.lensFlareLensStarburstTexture
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked
                text: qsTr("Direction")
                tooltip: qsTr("Sets the direction of the camera in the scene.")
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.lensFlareCameraDirection_x
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "X"
                    color: StudioTheme.Values.theme3DAxisXColor
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.lensFlareCameraDirection_y
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "Y"
                    color: StudioTheme.Values.theme3DAxisYColor
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: lensFlareEnabledCheckBox.checked
            }

            SecondColumnLayout {
                visible: lensFlareEnabledCheckBox.checked
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.lensFlareCameraDirection_z
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
        caption: qsTr("Other Effects")

        SectionLayout {
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
        }
    }
}
