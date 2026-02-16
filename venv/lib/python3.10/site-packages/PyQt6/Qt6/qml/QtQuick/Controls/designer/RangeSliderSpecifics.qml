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
        caption: qsTr("RangeSlider")

        SectionLayout {
            Label {
                text: qsTr("First Value")
                tooltip: qsTr("The value of the first range slider handle.")
            }
            SecondColumnLayout {
                SpinBox {
                    minimumValue: Math.min(backendValues.from.value, backendValues.to.value)
                    maximumValue: Math.max(backendValues.from.value, backendValues.to.value)
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.first_value
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("Second Value")
                tooltip: qsTr("The value of the second range slider handle.")
            }
            SecondColumnLayout {
                SpinBox {
                    minimumValue: Math.min(backendValues.from.value, backendValues.to.value)
                    maximumValue: Math.max(backendValues.from.value, backendValues.to.value)
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.second_value
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("From")
                tooltip: qsTr("The starting value of the range slider range.")
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
                tooltip: qsTr("The ending value of the range slider range.")
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
                tooltip: qsTr("The step size of the range slider.")
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
                tooltip: qsTr("The snap mode of the range slider.")
            }
            SecondColumnLayout {
                ComboBox {
                    backendValue: backendValues.snapMode
                    model: [ "NoSnap", "SnapOnRelease", "SnapAlways" ]
                    scope: "RangeSlider"
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("Orientation")
                tooltip: qsTr("The orientation of the range slider.")
            }
            SecondColumnLayout {
                ComboBox {
                    backendValue: backendValues.orientation
                    model: [ "Horizontal", "Vertical" ]
                    scope: "Qt"
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("Live")
                tooltip: qsTr("Whether the range slider provides live value updates.")
            }
            SecondColumnLayout {
                CheckBox {
                    text: backendValues.live.valueToString
                    backendValue: backendValues.live
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("Touch drag threshold")
                tooltip: qsTr("The threshold (in logical pixels) at which a touch drag event will be initiated.")
            }
            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 10000
                    decimals: 0
                    backendValue: backendValues.touchDragThreshold
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
