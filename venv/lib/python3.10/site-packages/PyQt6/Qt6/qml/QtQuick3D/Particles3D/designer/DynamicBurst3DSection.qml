// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Particle Dynamic Burst")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Trigger Mode")
            tooltip: qsTr("Sets the triggering mode used for emitting the particles.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "DynamicBurst3D"
                model: ["TriggerTime", "TriggerStart", "TriggerEnd"]
                backendValue: backendValues.triggerMode
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Amount Variation")
            tooltip: qsTr("Sets the random variation in particle emit amount.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 999999
                decimals: 0
                backendValue: backendValues.amountVariation
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Enabled")
            tooltip: qsTr("If set to false, this burst will not emit any particles. Usually this is used to conditionally turn a burst on or off.")
        }

        SecondColumnLayout {
            CheckBox {
                id: enabledCheckBox
                text: backendValues.enabled.valueToString
                backendValue: backendValues.enabled
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
