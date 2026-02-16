// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import HelperWidgets
import QtQuick.Layouts

Section {
    SectionLayout {
        Label {
            text: qsTr("Check State")
            tooltip: qsTr("The current check state.")
        }
        SecondColumnLayout {
            ComboBox {
                backendValue: backendValues.checkState
                model: [ "Unchecked", "PartiallyChecked", "Checked" ]
                scope: "Qt"
                Layout.fillWidth: true
            }
        }

        Label {
            text: qsTr("Tri-state")
            tooltip: qsTr("Whether the checkbox has three states.")
        }
        SecondColumnLayout {
            CheckBox {
                text: backendValues.tristate.valueToString
                backendValue: backendValues.tristate
                Layout.fillWidth: true
            }
        }
    }
}
