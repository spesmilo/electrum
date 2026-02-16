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
        caption: qsTr("Procedural Sky Texture Data")

        SectionLayout {

            PropertyLabel {
                text: qsTr("Quality")
                tooltip: qsTr("This property sets the size of the texture. The higher the quality, the more memory is used.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "ProceduralSkyTextureData"
                    model: ["SkyTextureQualityLow", "SkyTextureQualityMedium", "SkyTextureQualityHigh", "SkyTextureQualityVeryHigh"]
                    backendValue: backendValues.textureQuality
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        width: parent.width
        caption: qsTr("Sky")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Top Color")
                tooltip: qsTr("Specifies the sky color at the top of the skybox.")
            }

            ColorEditor {
                backendValue: backendValues.skyTopColor
                supportGradient: false
            }

            PropertyLabel {
                text: qsTr("Horizon Color")
                tooltip: qsTr("Specifies the sky color at the horizon.")
            }

            ColorEditor {
                backendValue: backendValues.skyHorizonColor
                supportGradient: false
            }

            PropertyLabel {
                text: qsTr("Energy")
                tooltip: qsTr("Specifies the HDR color intensity of the top half of the skybox.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 64
                    decimals: 3
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.skyEnergy
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Curve")
                tooltip: qsTr("Modifies the curve (n^x) of the sky gradient from the horizon to the top.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 64
                    decimals: 3
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.skyCurve
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        width: parent.width
        caption: qsTr("Ground")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Bottom Color")
                tooltip: qsTr("Specifies the ground color at the bottom of the skybox.")
            }

            ColorEditor {
                backendValue: backendValues.groundBottomColor
                supportGradient: false
            }

            PropertyLabel {
                text: qsTr("Horizon Color")
                tooltip: qsTr("Specifies the ground color at the horizon.")
            }

            ColorEditor {
                backendValue: backendValues.groundHorizonColor
                supportGradient: false
            }

            PropertyLabel {
                text: qsTr("Energy")
                tooltip: qsTr("Specifies the HDR color intensity of the bottom half of the skybox.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 64
                    decimals: 3
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.groundEnergy
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Curve")
                tooltip: qsTr("Modifies the curve (n^x) of the ground gradient from the horizon to the bottom.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 64
                    decimals: 3
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.groundCurve
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        width: parent.width
        caption: qsTr("Sun")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Color")
                tooltip: qsTr("Specifies the color at the sun on the skybox.")
            }

            ColorEditor {
                backendValue: backendValues.sunColor
                supportGradient: false
            }

            PropertyLabel {
                text: qsTr("Energy")
                tooltip: qsTr("Specifies the HDR color intensity of sun on the skybox.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 64
                    decimals: 3
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.sunEnergy
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Fade Start")
                tooltip: qsTr("Specifies the angle from the center of the sun to where it starts to fade.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 360
                    decimals: 1
                    stepSize: 0.1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.sunAngleMin
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Fade End")
                tooltip: qsTr("Specifies the angle from the center of the sun to where it fades out completely.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 360
                    decimals: 1
                    stepSize: 0.1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.sunAngleMax
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Curve")
                tooltip: qsTr("Modifies the curve (n^x) of the gradient from the sky color and the sun.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 64
                    decimals: 3
                    stepSize: 0.01
                    sliderIndicatorVisible: true
                    backendValue: backendValues.sunCurve
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Latitude")
                tooltip: qsTr("Specifies the angle between the horizon and the sun position.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -180
                    maximumValue: 180
                    decimals: 1
                    stepSize: 0.1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.sunLatitude
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Longitude")
                tooltip: qsTr("Specifies the angle between the forward direction and the sun position.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 360
                    decimals: 1
                    stepSize: 0.1
                    sliderIndicatorVisible: true
                    backendValue: backendValues.sunLongitude
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }
}
