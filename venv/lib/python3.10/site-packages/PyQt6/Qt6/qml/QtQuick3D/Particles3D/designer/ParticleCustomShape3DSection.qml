// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Particle Custom Shape")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Randomize Data")
            tooltip: qsTr("Sets whether the particles are used in random order instead of in the order they are specified in the source.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.castsShadows.valueToString
                backendValue: backendValues.castsShadows
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Source")
            tooltip: qsTr("Sets the location of the shape file.")
        }

        SecondColumnLayout {
            UrlChooser {
                id: sourceUrlChooser
                backendValue: backendValues.source
                filter: "*.cbor"
            }

            ExpandingSpacer {}
        }
    }
}
