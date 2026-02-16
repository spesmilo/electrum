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
        caption: qsTr("Infinite Grid")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Visible")
                tooltip: qsTr("Sets whether the infinite grid is visible.")
            }

            CheckBox {
                text: backendValues.visible.valueToString
                backendValue: backendValues.visible
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            PropertyLabel {
                text: qsTr("Axis Lines")
                tooltip: qsTr("Sets whether the axis lines are visible.")
            }

            CheckBox {
                text: backendValues.gridAxes ? qsTr("On") : qsTr("Off")
                backendValue: backendValues.gridAxes
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            PropertyLabel {
                text: qsTr("Grid Interval")
                tooltip: qsTr("Sets the distance between grid lines.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 9999999
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.gridInterval
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }
}
