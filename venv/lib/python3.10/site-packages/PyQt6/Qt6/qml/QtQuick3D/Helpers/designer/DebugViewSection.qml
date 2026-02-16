// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Column {
    width: parent.width

    Section {
        width: parent.width
        caption: qsTr("Debug View")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Source View")
                tooltip: qsTr("Sets the source View3D item to show render statistics for.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.View3D"
                    backendValue: backendValues.source
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Detailed Mode")
                tooltip: qsTr("Enables detailed mode, which shows more detailed resource usage statistics.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.resourceDetailsVisible.valueToString
                    backendValue: backendValues.resourceDetailsVisible
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }
}
