// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Column {
    width: parent.width

    Section {
        width: parent.width
        caption: qsTr("Axis Helper")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Axis Lines")
                tooltip: qsTr("Show colored axis indicator lines.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: qsTr("Enabled")
                    backendValue: backendValues.enableAxisLines
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("XY Grid")
                tooltip: qsTr("Show grid on XY plane.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: qsTr("Enabled")
                    backendValue: backendValues.enableXYGrid
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("XZ Grid")
                tooltip: qsTr("Show grid on XZ plane.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: qsTr("Enabled")
                    backendValue: backendValues.enableXZGrid
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }


            PropertyLabel {
                text: qsTr("YZ Grid")
                tooltip: qsTr("Show grid on YZ plane.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: qsTr("Enabled")
                    backendValue: backendValues.enableYZGrid
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Grid Opacity")
                tooltip: qsTr("Sets the opacity of the visible grids.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.gridOpacity
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Grid Color")
                tooltip: qsTr("Sets the color of the visible grids.")
            }

            ColorEditor {
                backendValue: backendValues.gridColor
                supportGradient: false
            }
        }
    }
}
