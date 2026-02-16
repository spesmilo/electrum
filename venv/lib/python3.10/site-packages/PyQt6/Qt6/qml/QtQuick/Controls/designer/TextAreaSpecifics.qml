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
        caption: qsTr("TextArea")

        SectionLayout {
            Label {
                text: qsTr("Placeholder")
                tooltip: qsTr("Placeholder text displayed when the editor is empty.")
            }
            SecondColumnLayout {
                LineEdit {
                    backendValue: backendValues.placeholderText
                    Layout.fillWidth: true
                }

            }

            Label {
                text: qsTr("Hover")
                tooltip: qsTr("Whether text area accepts hover events.")
            }
            SecondColumnLayout {
                CheckBox {
                    text: backendValues.hoverEnabled.valueToString
                    backendValue: backendValues.hoverEnabled
                    Layout.fillWidth: true
                }
            }
        }
    }

    Section {
        width: parent.width
        caption: qsTr("Placeholder Text Color")

        ColorEditor {
            caption: qsTr("Placeholder Text Color")
            backendValue: backendValues.placeholderTextColor
            supportGradient: false
        }
    }

    StandardTextSection {
        width: parent.width
        showIsWrapping: true
        showFormatProperty: true
        showVerticalAlignment: true
    }

    FontSection {
        width: parent.width
    }

    PaddingSection {
        width: parent.width
    }

    InsetSection {
        width: parent.width
    }
}
