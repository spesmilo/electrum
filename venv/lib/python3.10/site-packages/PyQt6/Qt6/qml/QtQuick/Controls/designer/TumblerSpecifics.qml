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
        caption: qsTr("Tumbler")

        SectionLayout {
            Label {
                text: qsTr("Visible Count")
                tooltip: qsTr("The count of visible items.")
            }
            SecondColumnLayout {
                SpinBox {
                    maximumValue: 9999999
                    minimumValue: -9999999
                    decimals: 0
                    backendValue: backendValues.visibleItemCount
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("Current")
                tooltip: qsTr("The index of the current item.")
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
                text: qsTr("Wrap")
                tooltip: qsTr("Whether the tumbler wrap.")
            }
            SecondColumnLayout {
                CheckBox {
                    text: backendValues.wrap.valueToString
                    backendValue: backendValues.wrap
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("flickDeceleration")
                tooltip: qsTr("The rate at which a flick will decelerate.")
            }
            SecondColumnLayout {
                SpinBox {
                    maximumValue: 9999999
                    minimumValue: 0
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.flickDeceleration
                    Layout.fillWidth: true
                }
            }
        }
    }

    ControlSection {
        width: parent.width
    }

    FontSection {
        width: parent.width
    }

    PaddingSection {
        width: parent.width
    }
}
