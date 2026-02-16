// Copyright (C) 2023 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Lightmapper")
    width: parent.width

    SectionLayout {

        PropertyLabel {
            text: qsTr("Adaptive Bias")
            tooltip: qsTr("Enables additional dynamic biasing based on the surface normal.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.adaptiveBiasEnabled.valueToString
                backendValue: backendValues.adaptiveBiasEnabled
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Bias")
            tooltip: qsTr("Raycasting bias to avoid self-intersection artifacts.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: -9999999
                maximumValue: 9999999
                decimals: 5
                stepSize: 0.001
                backendValue: backendValues.bias
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Opacity Threshold")
            tooltip: qsTr("Bounces against materials with opacity values below this threshold are ignored when calculating lighting via raytracing.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 1
                decimals: 2
                stepSize: 0.01
                sliderIndicatorVisible: true
                backendValue: backendValues.opacityThreshold
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Samples")
            tooltip: qsTr("The number of samples per lightmap texel.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 2048
                decimals: 0
                stepSize: 16
                sliderIndicatorVisible: true
                backendValue: backendValues.samples
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Indirect Lighting")
            tooltip: qsTr("Enables the baking of indirect lighting.")
        }

        SecondColumnLayout {
            CheckBox {
                id: indirectLightEnabledCheckBox
                text: backendValues.indirectLightEnabled.valueToString
                backendValue: backendValues.indirectLightEnabled
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            visible: indirectLightEnabledCheckBox.checked
            text: qsTr("Bounces")
            tooltip: qsTr("The maximum number of indirect light bounces per sample.")
        }

        SecondColumnLayout {
            visible: indirectLightEnabledCheckBox.checked
            SpinBox {
                minimumValue: 1
                maximumValue: 16
                decimals: 0
                stepSize: 1
                backendValue: backendValues.bounces
                sliderIndicatorVisible: true
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            visible: indirectLightEnabledCheckBox.checked
            text: qsTr("Indirect Light Factor")
            tooltip: qsTr("Multiplier for the indirect light amount.")
        }

        SecondColumnLayout {
            visible: indirectLightEnabledCheckBox.checked
            SpinBox {
                minimumValue: 0
                maximumValue: 10
                decimals: 2
                stepSize: 0.01
                backendValue: backendValues.indirectLightFactor
                sliderIndicatorVisible: true
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            visible: indirectLightEnabledCheckBox.checked
            text: qsTr("Indirect Workgroup Size")
            tooltip: qsTr("The size of the workgroup used for indirect light computation.")
        }

        SecondColumnLayout {
            visible: indirectLightEnabledCheckBox.checked
            SpinBox {
                minimumValue: 1
                maximumValue: 512
                decimals: 0
                stepSize: 1
                backendValue: backendValues.indirectLightWorkgroupSize
                sliderIndicatorVisible: true
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

    }
}
