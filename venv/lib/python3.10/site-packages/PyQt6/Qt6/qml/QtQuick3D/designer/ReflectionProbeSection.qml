// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Reflection Probe")

    SectionLayout {
        PropertyLabel {
            text: qsTr("Box Size")
            tooltip: qsTr("Sets the reflection probe box size.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 9999999
                decimals: 2
                backendValue: backendValues.boxSize_x
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "box size x"
                color: StudioTheme.Values.theme3DAxisXColor
            }

            ExpandingSpacer {}
        }

        PropertyLabel {}

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 9999999
                decimals: 2
                backendValue: backendValues.boxSize_y
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "box size y"
                color: StudioTheme.Values.theme3DAxisYColor
            }

            ExpandingSpacer {}
        }

        PropertyLabel {}

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 9999999
                decimals: 2
                backendValue: backendValues.boxSize_z
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "box size z"
                color: StudioTheme.Values.theme3DAxisZColor
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Box Offset")
            tooltip: qsTr("Sets the reflection probe box position relative to the probe position.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: -9999999
                maximumValue: 9999999
                decimals: 2
                backendValue: backendValues.boxOffset_x
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "box offset x"
                color: StudioTheme.Values.theme3DAxisXColor
            }

            ExpandingSpacer {}
        }

        PropertyLabel {}

        SecondColumnLayout {
            SpinBox {
                minimumValue: -9999999
                maximumValue: 9999999
                decimals: 2
                backendValue: backendValues.boxOffset_y
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "box offset y"
                color: StudioTheme.Values.theme3DAxisYColor
            }

            ExpandingSpacer {}
        }

        PropertyLabel {}

        SecondColumnLayout {
            SpinBox {
                minimumValue: -9999999
                maximumValue: 9999999
                decimals: 2
                backendValue: backendValues.boxOffset_z
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "box offset z"
                color: StudioTheme.Values.theme3DAxisZColor
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Parallax Correction")
            tooltip: qsTr("Reflection maps are considered to be at infinite distance by default. This is unsuitable for indoor area as it produces parallax issues.\nSetting this property to true corrects the cubemap by taking the camera position and the box's dimension into account.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.parallaxCorrection.valueToString
                backendValue: backendValues.parallaxCorrection
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Debug View")
            tooltip: qsTr("Enables rendering a wireframe to visualize the reflection probe box.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.debugView.valueToString
                backendValue: backendValues.debugView
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Clear Color")
            tooltip: qsTr("Sets the color that will be used to clear the reflection map.")
        }

        ColorEditor {
            backendValue: backendValues.clearColor
            supportGradient: false
        }

        PropertyLabel {
            text: qsTr("Reflection Map Quality")
            tooltip: qsTr("Sets the quality of the reflection map.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "ReflectionProbe"
                model: ["VeryLow", "Low", "Medium", "High", "VeryHigh"]
                backendValue: backendValues.quality
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Refresh Mode")
            tooltip: qsTr("Sets how often the reflection map will be updated.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "ReflectionProbe"
                model: ["FirstFrame", "EveryFrame"]
                backendValue: backendValues.refreshMode
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Time Slicing")
            tooltip: qsTr("Sets how often the faces of the reflection cube map are updated.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "ReflectionProbe"
                model: ["None", "AllFacesAtOnce", "IndividualFaces"]
                backendValue: backendValues.timeSlicing
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Override Texture")
            tooltip: qsTr("Sets an override texture to use for the reflection map instead of rendering the scene.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.CubeMapTexture"
                backendValue: backendValues.texture
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
