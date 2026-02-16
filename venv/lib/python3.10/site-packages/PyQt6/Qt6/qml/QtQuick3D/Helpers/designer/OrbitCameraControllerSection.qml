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
        caption: qsTr("Orbit Camera Controller")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Origin")
                tooltip: qsTr("The node that the camera will orbit around.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Node"
                    backendValue: backendValues.origin
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Camera")
                tooltip: qsTr("The camera that will be controlled.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Camera"
                    backendValue: backendValues.camera
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Mouse/Touch")
                tooltip: qsTr("Enables interaction via mouse and touch.")
            }

            SecondColumnLayout {
                CheckBox {
                    id: mouseEnabledCheckBox
                    text: backendValues.mouseEnabled.valueToString
                    backendValue: backendValues.mouseEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: mouseEnabledCheckBox.checked
                text: qsTr("Pan Controls")
                tooltip: qsTr("Enables panning gestures.")
            }

            SecondColumnLayout {
                visible: mouseEnabledCheckBox.checked
                CheckBox {
                    text: backendValues.panEnabled.valueToString
                    backendValue: backendValues.panEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: mouseEnabledCheckBox.checked
                text: qsTr("Invert X")
                tooltip: qsTr("Enables inverting X-axis controls.")
            }

            SecondColumnLayout {
                visible: mouseEnabledCheckBox.checked
                CheckBox {
                    text: backendValues.xInvert.valueToString
                    backendValue: backendValues.xInvert
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: mouseEnabledCheckBox.checked
                text: qsTr("X Speed")
                tooltip: qsTr("The speed of the X-axis controls.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 999999
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.xSpeed
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: mouseEnabledCheckBox.checked
                text: qsTr("Invert Y")
                tooltip: qsTr("Enables inverting Y-axis controls.")
            }

            SecondColumnLayout {
                visible: mouseEnabledCheckBox.checked
                CheckBox {
                    text: backendValues.yInvert.valueToString
                    backendValue: backendValues.yInvert
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: mouseEnabledCheckBox.checked
                text: qsTr("Y Speed")
                tooltip: qsTr("The speed of the Y-axis controls.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 999999
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.ySpeed
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

        }
    }
}
