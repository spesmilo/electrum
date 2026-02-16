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
        caption: qsTr("Slider")

        SectionLayout {
            Label {
                text: qsTr("Value")
                tooltip: qsTr("The current value of the slider.")
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
                tooltip: qsTr("The starting value of the slider range.")
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
                tooltip: qsTr("The ending value of the slider range.")
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
                tooltip: qsTr("The step size of the slider.")
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
                tooltip: qsTr("The snap mode of the slider.")
                disabledState: !backendValues.snapMode.isAvailable
            }
            SecondColumnLayout {
                ComboBox {
                    backendValue: backendValues.snapMode
                    model: [ "NoSnap", "SnapOnRelease", "SnapAlways" ]
                    scope: "Slider"
                    Layout.fillWidth: true
                    enabled: backendValue.isAvailable
                }
            }

            Label {
                text: qsTr("Orientation")
                tooltip: qsTr("The orientation of the slider.")
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
                tooltip: qsTr("Whether the slider provides live value updates.")
                disabledState: !backendValues.live.isAvailable
            }
            SecondColumnLayout {
                CheckBox {
                    text: backendValues.live.valueToString
                    backendValue: backendValues.live
                    Layout.fillWidth: true
                    enabled: backendValue.isAvailable
                }
            }

            Label {
                text: qsTr("Touch drag threshold")
                tooltip: qsTr("The threshold (in logical pixels) at which a touch drag event will be initiated.")
                disabledState: !backendValues.touchDragThreshold.isAvailable
            }
            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 10000
                    decimals: 0
                    backendValue: backendValues.touchDragThreshold
                    Layout.fillWidth: true
                    enabled: backendValue.isAvailable
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
