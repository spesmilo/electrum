// Copyright (C) 2023 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Instancing")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Depth Sorting")
            tooltip: qsTr("Enable depth sorting for instanced objects.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.depthSortingEnabled.valueToString
                backendValue: backendValues.depthSortingEnabled
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Has Transparency")
            tooltip: qsTr("Set this to true if the instancing table contains alpha values that should be used when rendering the model.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.hasTransparency.valueToString
                backendValue: backendValues.hasTransparency
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Instance Count")
            tooltip: qsTr("Sets a limit on the number of instances that can be rendered regardless of the number of instances in the instancing table.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: -1
                maximumValue: 9999999
                decimals: 0
                stepSize: 1
                backendValue: backendValues.instanceCountOverride
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

    }
}
