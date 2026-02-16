// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Vignette")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Strength")
            tooltip: qsTr("Set the vignette strength.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 15
                decimals: 2
                backendValue: backendValues.vignetteStrength
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Radius")
            tooltip: qsTr("Set the vignette radius.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 5
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.vignetteRadius
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel { text: qsTr("Vignette Color") }

        ColorEditor {
            backendValue: backendValues.vignetteColor
            supportGradient: false
            isVector3D: true
        }
    }
}
