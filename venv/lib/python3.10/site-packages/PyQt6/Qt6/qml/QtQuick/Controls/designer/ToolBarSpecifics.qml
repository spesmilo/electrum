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
        caption: qsTr("ToolBar")

        SectionLayout {
            Label {
                text: qsTr("Position")
                tooltip: qsTr("Position of the toolbar.")
            }
            SecondColumnLayout {
                ComboBox {
                    backendValue: backendValues.position
                    model: [ "Header", "Footer" ]
                    scope: "ToolBar"
                    Layout.fillWidth: true
                }
            }
        }
    }

    PaneSection {
        width: parent.width
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
