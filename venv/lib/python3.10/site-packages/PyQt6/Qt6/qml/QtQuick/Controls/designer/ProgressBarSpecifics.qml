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
        caption: qsTr("ProgressBar")

        SectionLayout {
            Label {
                text: qsTr("Indeterminate")
                tooltip: qsTr("Whether the progress is indeterminate.")
                disabledState: !backendValues.indeterminate.isAvailable
            }
            SecondColumnLayout {
                CheckBox {
                    text: backendValues.indeterminate.valueToString
                    backendValue: backendValues.indeterminate
                    Layout.fillWidth: true
                    enabled: backendValue.isAvailable
                }
            }

            Label {
                text: qsTr("Value")
                tooltip: qsTr("The current value of the progress.")
            }
            SecondColumnLayout {
                SpinBox {
                    minimumValue: Math.min(backendValues.from.value, backendValues.to.value)
                    maximumValue: Math.max(backendValues.from.value, backendValues.to.value)
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.value
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("From")
                tooltip: qsTr("The starting value for the progress.")
            }
            SecondColumnLayout {
                SpinBox {
                    maximumValue: 9999999
                    minimumValue: -9999999
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.from
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("To")
                tooltip: qsTr("The ending value for the progress.")
            }
            SecondColumnLayout {
                SpinBox {
                    maximumValue: 9999999
                    minimumValue: -9999999
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.to
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
