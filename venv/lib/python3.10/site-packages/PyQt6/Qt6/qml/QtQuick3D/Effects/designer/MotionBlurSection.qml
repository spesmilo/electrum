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
            text: qsTr("Fade Amount")
            tooltip: qsTr("Specifies how much the blur fades away each frame.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 1
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.fadeAmount
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Quality")
            tooltip: qsTr("Blur quality.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0.1
                maximumValue: 1
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.blurQuality
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
