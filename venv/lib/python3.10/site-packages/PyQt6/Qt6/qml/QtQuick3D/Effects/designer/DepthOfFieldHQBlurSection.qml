// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Blur")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Blur Amount")
            tooltip: qsTr("Amount of blur.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 50
                decimals: 2
                backendValue: backendValues.blurAmount
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Focus Distance")
            tooltip: qsTr("Focus distance of the blur.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 5000
                decimals: 0
                backendValue: backendValues.focusDistance
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Focus Range")
            tooltip: qsTr("Focus range of the blur.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 5000
                decimals: 0
                backendValue: backendValues.focusRange
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
