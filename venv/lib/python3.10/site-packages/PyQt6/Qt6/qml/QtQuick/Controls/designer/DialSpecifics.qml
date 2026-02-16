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
        caption: qsTr("Dial")

        SectionLayout {
            Label {
                text: qsTr("Value")
                tooltip: qsTr("The current value of the dial.")
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
                tooltip: qsTr("The starting value of the dial range.")
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
                tooltip: qsTr("The ending value of the dial range.")
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

            Label {
                text: qsTr("Step Size")
                tooltip: qsTr("The step size of the dial.")
            }
            SecondColumnLayout {
                SpinBox {
                    maximumValue: 9999999
                    minimumValue: -9999999
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.stepSize
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("Snap Mode")
                tooltip: qsTr("The snap mode of the dial.")
            }
            SecondColumnLayout {
                ComboBox {
                    backendValue: backendValues.snapMode
                    model: [ "NoSnap", "SnapOnRelease", "SnapAlways" ]
                    scope: "Dial"
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("Live")
                tooltip: qsTr("Whether the dial provides live value updates.")
            }
            SecondColumnLayout {
                CheckBox {
                    text: backendValues.live.valueToString
                    backendValue: backendValues.live
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("Input Mode")
                tooltip: qsTr("How the dial tracks movement.")
            }
            SecondColumnLayout {
                ComboBox {
                    backendValue: backendValues.inputMode
                    model: [ "Circular", "Horizontal", "Vertical" ]
                    scope: "Dial"
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("Wrap")
                tooltip: qsTr("Whether the dial wraps when dragged.")
            }
            SecondColumnLayout {
                CheckBox {
                    text: backendValues.wrap.valueToString
                    backendValue: backendValues.wrap
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
