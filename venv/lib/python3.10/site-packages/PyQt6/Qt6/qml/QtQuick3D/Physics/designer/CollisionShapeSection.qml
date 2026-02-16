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
        caption: qsTr("Collision Shape")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Debug Draw")
                tooltip: qsTr("Draws the collision shape in the scene view.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.enableDebugDraw.valueToString
                    backendValue: backendValues.enableDebugDraw
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }
}
