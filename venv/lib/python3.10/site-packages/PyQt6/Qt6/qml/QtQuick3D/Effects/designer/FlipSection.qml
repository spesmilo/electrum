// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Flip")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Horizontal")
            tooltip: qsTr("Flip horizontally.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.flipHorizontally.valueToString
                backendValue: backendValues.flipHorizontally
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Vertical")
            tooltip: qsTr("Flip vertically.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.flipVertically.valueToString
                backendValue: backendValues.flipVertically
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
