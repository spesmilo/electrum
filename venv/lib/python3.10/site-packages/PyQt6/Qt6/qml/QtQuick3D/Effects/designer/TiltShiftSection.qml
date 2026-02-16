// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Tilt Shift")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Focus Position")
            tooltip: qsTr("Set the focus position.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 1
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.focusPosition
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Focus Width")
            tooltip: qsTr("Set the focus width.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 1
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.focusWidth
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Blur Amount")
            tooltip: qsTr("Set the blur amount.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 10
                decimals: 2
                backendValue: backendValues.blurAmount
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Vertical")
            tooltip: qsTr("Specifies if the tilt shift is vertical.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.isVertical.valueToString
                backendValue: backendValues.isVertical
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Inverted")
            tooltip: qsTr("Specifies if the tilt shift is inverted.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.isInverted.valueToString
                backendValue: backendValues.isInverted
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
