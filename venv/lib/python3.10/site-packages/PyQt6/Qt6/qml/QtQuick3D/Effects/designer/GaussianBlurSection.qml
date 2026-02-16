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
            text: qsTr("Amount")
            tooltip: qsTr("Strength of the blur.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 10
                decimals: 2
                backendValue: backendValues.amount
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
