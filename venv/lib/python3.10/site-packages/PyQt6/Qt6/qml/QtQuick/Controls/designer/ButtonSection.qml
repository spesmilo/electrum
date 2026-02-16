// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import HelperWidgets
import QtQuick.Layouts

Section {
    id: section
    caption: qsTr("Button")

    SectionLayout {

        Label {
            text: qsTr("Flat")
            tooltip: qsTr("Whether the button is flat.")
            disabledState: !backendValues.flat.isAvailable
        }
        SecondColumnLayout {
            CheckBox {
                text: backendValues.flat.valueToString
                backendValue: backendValues.flat
                Layout.fillWidth: true
                enabled: backendValue.isAvailable
            }
        }
        Label {
            text: qsTr("Highlighted")
            tooltip: qsTr("Whether the button is highlighted.")
            disabledState: !backendValues.highlighted.isAvailable
        }
        SecondColumnLayout {
            CheckBox {
                text: backendValues.highlighted.valueToString
                backendValue: backendValues.highlighted
                Layout.fillWidth: true
                enabled: backendValue.isAvailable
            }
        }
    }
}
