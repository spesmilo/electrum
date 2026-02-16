// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Cascades")
    width: parent.width

    SectionLayout {

        PropertyLabel {
            text: qsTr("No. Splits")
            tooltip: qsTr("The number of cascade splits for this light.")
        }

        SecondColumnLayout {
            ComboBox {
                id: numSplitsComboBox
                valueType: ComboBox.ValueType.Integer
                model: [0, 1, 2, 3]
                backendValue: backendValues.csmNumSplits
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            visible: numSplitsComboBox.currentIndex > 0
            text: qsTr("Blend ratio")
            tooltip: qsTr("Defines how much of the shadow of any cascade should be blended together with the previous one.")
        }

        SecondColumnLayout {
            visible: numSplitsComboBox.currentIndex > 0
            SpinBox {
                minimumValue: 0
                maximumValue: 1
                decimals: 2
                stepSize: 0.01
                backendValue: backendValues.csmBlendRatio
                sliderIndicatorVisible: true
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            visible: numSplitsComboBox.currentIndex > 0
            text: qsTr("Split 1")
            tooltip: qsTr("Defines where the first cascade of the shadow map split will occur.")
        }

        SecondColumnLayout {
            visible: numSplitsComboBox.currentIndex > 0
            SpinBox {
                minimumValue: 0
                maximumValue: 1
                decimals: 2
                stepSize: 0.01
                backendValue: backendValues.csmSplit1
                sliderIndicatorVisible: true
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            visible: numSplitsComboBox.currentIndex > 1
            text: qsTr("Split 2")
            tooltip: qsTr("Defines where the second cascade of the shadow map split will occur.")
        }

        SecondColumnLayout {
            visible: numSplitsComboBox.currentIndex > 1
            SpinBox {
                minimumValue: 0
                maximumValue: 1
                decimals: 2
                stepSize: 0.01
                backendValue: backendValues.csmSplit2
                sliderIndicatorVisible: true
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            visible: numSplitsComboBox.currentIndex > 2
            text: qsTr("Split 3")
            tooltip: qsTr("Defines where the third cascade of the shadow map split will occur.")
        }

        SecondColumnLayout {
            visible: numSplitsComboBox.currentIndex > 2
            SpinBox {
                minimumValue: 0
                maximumValue: 1
                decimals: 2
                stepSize: 0.01
                backendValue: backendValues.csmSplit3
                sliderIndicatorVisible: true
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Lock Shadowmap Texels")
            tooltip: qsTr("Locks the shadowmap texels for this light to remove shadow edge shimmering.")
        }

        SecondColumnLayout {
            CheckBox {
                id: lockShadowmapTexelsCheckBox
                text: backendValues.lockShadowmapTexels.valueToString
                backendValue: backendValues.lockShadowmapTexels
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }
            ExpandingSpacer {}
        }
    }
}
