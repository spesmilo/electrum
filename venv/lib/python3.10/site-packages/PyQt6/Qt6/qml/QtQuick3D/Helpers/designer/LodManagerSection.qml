// Copyright (C) 2023 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Lod Manager")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Camera")
            tooltip: qsTr("Specifies the camera from which the distance to the child nodes is calculated.")
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
            text: qsTr("Fade Distance")
            tooltip: qsTr("Specifies the distance at which the cross-fade between the detail levels starts.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 999999
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.fadeDistance
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Distances")
            tooltip: qsTr("Specifies the thresholds when the detail level changes. The first number is the distance when the first node changes to the second one, etc.")
        }

        SecondColumnLayout {

            ActionIndicator {
                    icon.color: extFuncLogic.color
                    icon.text: extFuncLogic.glyph
                    onClicked: extFuncLogic.show()
                    forceVisible: extFuncLogic.menuVisible
                ExtendedFunctionLogic {
                    id: extFuncLogic
                    backendValue: backendValues.distances
                }
            }

            // Placeholder until we can do list of value types: QDS-9090
            Label {
                text: qsTr("Currently only editable in QML.")
                Layout.fillWidth: true
                Layout.preferredWidth: StudioTheme.Values.singleControlColumnWidth
                Layout.minimumWidth: StudioTheme.Values.singleControlColumnWidth
                Layout.maximumWidth: StudioTheme.Values.singleControlColumnWidth
            }

            ExpandingSpacer {}
        }

    }
}
