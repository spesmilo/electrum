// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import HelperWidgets
import QtQuick.Layouts

Section {
    caption: qsTr("Control")

    SectionLayout {
        Label {
            text: qsTr("Enabled")
            tooltip: qsTr("Whether the control is enabled.")
        }
        SecondColumnLayout {
            CheckBox {
                text: backendValues.enabled.valueToString
                backendValue: backendValues.enabled
                Layout.fillWidth: true
            }
        }

        Label {
            text: qsTr("Focus Policy")
            tooltip: qsTr("Focus policy of the control.")
            disabledState: !backendValues.focusPolicy.isAvailable
        }
        SecondColumnLayout {
            ComboBox {
                backendValue: backendValues.focusPolicy
                model: [ "TabFocus", "ClickFocus", "StrongFocus", "WheelFocus", "NoFocus" ]
                scope: "Qt"
                Layout.fillWidth: true
                enabled: backendValue.isAvailable
            }
        }

        Label {
            text: qsTr("Hover")
            tooltip: qsTr("Whether control accepts hover events.")
            disabledState: !backendValues.hoverEnabled.isAvailable
        }
        SecondColumnLayout {
            CheckBox {
                text: backendValues.hoverEnabled.valueToString
                backendValue: backendValues.hoverEnabled
                Layout.fillWidth: true
                enabled: backendValue.isAvailable
            }
        }

        Label {
            text: qsTr("Spacing")
            tooltip: qsTr("Spacing between internal elements of the control.")
        }
        SecondColumnLayout {
            SpinBox {
                maximumValue: 9999999
                minimumValue: -9999999
                decimals: 0
                backendValue: backendValues.spacing
                Layout.fillWidth: true
            }
        }

        Label {
            text: qsTr("Wheel")
            tooltip: qsTr("Whether control accepts wheel events.")
            disabledState: !backendValues.wheelEnabled.isAvailable
        }
        SecondColumnLayout {
            CheckBox {
                text: backendValues.wheelEnabled.valueToString
                backendValue: backendValues.wheelEnabled
                Layout.fillWidth: true
                enabled: backendValue.isAvailable
            }
        }
    }
}
