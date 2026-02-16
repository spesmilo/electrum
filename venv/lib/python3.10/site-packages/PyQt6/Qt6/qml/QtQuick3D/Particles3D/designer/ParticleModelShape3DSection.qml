// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Particle Model Shape")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Fill")
            tooltip: qsTr("Sets if the shape should be filled or just use the shape outlines.")
        }

        SecondColumnLayout {
            CheckBox {
                id: fillCheckBox
                text: backendValues.fill.valueToString
                backendValue: backendValues.fill
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Delegate")
            tooltip: qsTr("The delegate provides a template defining the model for the ParticleModelShape3D.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "Component"
                backendValue: backendValues.delegate
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
