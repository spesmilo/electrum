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
        caption: qsTr("BusyIndicator")

        SectionLayout {
            Label {
                text: qsTr("Running")
                tooltip: qsTr("Whether the busy indicator is currently indicating activity.")
            }
            SecondColumnLayout {
                CheckBox {
                    text: backendValues.running.valueToString
                    backendValue: backendValues.running
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
