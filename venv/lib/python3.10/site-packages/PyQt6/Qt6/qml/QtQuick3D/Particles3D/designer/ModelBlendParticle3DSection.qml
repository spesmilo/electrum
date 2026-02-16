// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Model Blend Particle")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Delegate")
            tooltip: qsTr("The delegate provides a template defining the model for the ModelBlendParticle3D.")
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

        PropertyLabel {
            text: qsTr("End Node")
            tooltip: qsTr("Sets the node that specifies the transformation for the model at the end of particle effect.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.Node"
                backendValue: backendValues.endNode
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Model Blend Mode")
            tooltip: qsTr("Sets blending mode for the particle effect.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "ModelBlendParticle3D"
                model: ["Explode", "Construct", "Transfer"]
                backendValue: backendValues.modelBlendMode
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("End Time")
            tooltip: qsTr("Sets the end time of the particle in milliseconds.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 999999
                decimals: 0
                backendValue: backendValues.endTime
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Activation Node")
            tooltip: qsTr("Sets a node that activates particles.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.Node"
                backendValue: backendValues.activationNode
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Emit Mode")
            tooltip: qsTr("Sets emit mode of the particles.")
        }

        SecondColumnLayout {
            ComboBox {
                id: randomCheckBox
                model: ["Sequential", "Random", "Activation"]
                backendValue: backendValues.emitMode
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }

}
