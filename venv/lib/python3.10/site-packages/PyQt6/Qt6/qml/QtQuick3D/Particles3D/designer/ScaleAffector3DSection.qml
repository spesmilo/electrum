// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Particle Scale Affector")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Scaling Type")
            tooltip: qsTr("Sets the scaling type of the affector.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "ScaleAffector3D"
                model: ["Linear", "SewSaw", "SineWave", "AbsSineWave", "Step", "SmoothStep"]
                backendValue: backendValues.type
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Minimum Size")
            tooltip: qsTr("Sets the minimum scale size.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 999999
                decimals: 2
                backendValue: backendValues.minSize
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Maximum Size")
            tooltip: qsTr("Sets the maximum scale size.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 999999
                decimals: 2
                backendValue: backendValues.maxSize
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Duration")
            tooltip: qsTr("Sets the duration of scaling period.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 999999
                decimals: 0
                stepSize: 10
                backendValue: backendValues.duration
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Easing curve")
            tooltip: qsTr("Sets a custom scaling curve.")
        }

        SecondColumnLayout {
            BoolButtonRowButton {
                buttonIcon: StudioTheme.Constants.curveDesigner

                EasingCurveEditor {
                    id: easingCurveEditor
                    modelNodeBackendProperty: modelNodeBackend
                }

                onClicked: easingCurveEditor.runDialog()
            }

            ExpandingSpacer {}
        }
    }
}
