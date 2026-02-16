// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import HelperWidgets
import QtQuick.Layouts

Column {
    width: parent.width

    Section {
        width: parent.width
        caption: qsTr("PageIndicator")

        SectionLayout {
            Label {
                text: qsTr("Count")
                tooltip: qsTr("The number of pages.")
            }
            SecondColumnLayout {
                SpinBox {
                    maximumValue: 9999999
                    minimumValue: -9999999
                    decimals: 0
                    backendValue: backendValues.count
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("Current")
                tooltip: qsTr("The index of the current page.")
            }
            SecondColumnLayout {
                SpinBox {
                    maximumValue: 9999999
                    minimumValue: -9999999
                    decimals: 0
                    backendValue: backendValues.currentIndex
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("Interactive")
                tooltip: qsTr("Whether the control is interactive.")
            }
            SecondColumnLayout {
                CheckBox {
                    text: backendValues.interactive.valueToString
                    backendValue: backendValues.interactive
                    Layout.fillWidth: true
                }
            }
        }
    }

    ControlSection {
        width: parent.width
    }

    PaddingSection {
        width: parent.width
    }
}
