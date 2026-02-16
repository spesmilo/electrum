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
        caption: qsTr("ComboBox")

        SectionLayout {
            Label {
                text: qsTr("Text Role")
                tooltip: qsTr("The model role used for displaying text.")
            }
            SecondColumnLayout {
                LineEdit {
                    backendValue: backendValues.textRole
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
            text: qsTr("Editable")
            tooltip: qsTr("Whether the combo box is editable.")
        }
        SecondColumnLayout {
            CheckBox {
                text: backendValues.editable.valueToString
                backendValue: backendValues.editable
                Layout.fillWidth: true
            }
        }
        Label {
            text: qsTr("Flat")
            tooltip: qsTr("Whether the combo box button is flat.")
        }
        SecondColumnLayout {
            CheckBox {
                text: backendValues.flat.valueToString
                backendValue: backendValues.flat
                Layout.fillWidth: true
            }
        }
        Label {
                text: qsTr("DisplayText")
                tooltip: qsTr("Holds the text that is displayed on the combo box button.")
            }
            SecondColumnLayout {
                LineEdit {
                    backendValue: backendValues.displayText
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
