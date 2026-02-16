// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Distortion")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Radius")
            tooltip: qsTr("Radius of the effect.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 1
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.radius
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Height")
            tooltip: qsTr("Height of the distortion.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: -1
                maximumValue: 1
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.distortionHeight
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Center")
            tooltip: qsTr("Center of the distortion.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 1
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.center_x
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                            + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel { text: "X" }

            Spacer { implicitWidth: StudioTheme.Values.controlGap }

            SpinBox {
                minimumValue: 0
                maximumValue: 1
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.center_y
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                            + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel { text: "Y" }

            Spacer { implicitWidth: StudioTheme.Values.controlGap }

            ExpandingSpacer {}
        }
    }
}
