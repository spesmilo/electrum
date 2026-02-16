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
        caption: qsTr("SwipeView")

        SectionLayout {
            Label {
                text: qsTr("Interactive")
                tooltip: qsTr("Whether the view is interactive.")
            }
            SecondColumnLayout {
                CheckBox {
                    text: backendValues.interactive.valueToString
                    backendValue: backendValues.interactive
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr("Orientation")
                tooltip: qsTr("Orientation of the view.")
            }
            SecondColumnLayout {
                ComboBox {
                    backendValue: backendValues.orientation
                    model: [ "Horizontal", "Vertical" ]
                    scope: "Qt"
                    Layout.fillWidth: true
                }
            }
        }
    }

    ContainerSection {
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
