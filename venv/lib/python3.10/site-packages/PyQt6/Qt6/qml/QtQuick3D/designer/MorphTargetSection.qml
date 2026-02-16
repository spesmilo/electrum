// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Morph Target")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Weight")
            tooltip: qsTr("Sets the weight of the current morph target.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: -9999999
                maximumValue: 9999999
                decimals: 2
                backendValue: backendValues.weight
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Attributes")
            tooltip: qsTr("Sets the set of attributes of the current morph target.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "MorphTarget"
                model: ["Position", "Normal", "Tangent", "Binormal"]
                backendValue: backendValues.attributes
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
