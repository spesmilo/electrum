// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import HelperWidgets
import QtQuick.Layouts

Section {
    caption: qsTr("Padding")

    SectionLayout {
        Label {
            text: qsTr("Top")
            tooltip: qsTr("Padding between the content and the top edge of the control.")
        }
        SecondColumnLayout {
            SpinBox {
                maximumValue: 9999999
                minimumValue: -9999999
                decimals: 0
                backendValue: backendValues.topPadding
                Layout.fillWidth: true
            }
        }

        Label {
            text: qsTr("Left")
            tooltip: qsTr("Padding between the content and the left edge of the control.")
        }
        SecondColumnLayout {
            SpinBox {
                maximumValue: 9999999
                minimumValue: -9999999
                decimals: 0
                backendValue: backendValues.leftPadding
                Layout.fillWidth: true
            }
        }

        Label {
            text: qsTr("Right")
            tooltip: qsTr("Padding between the content and the right edge of the control.")
        }
        SecondColumnLayout {
            SpinBox {
                maximumValue: 9999999
                minimumValue: -9999999
                decimals: 0
                backendValue: backendValues.rightPadding
                Layout.fillWidth: true
            }
        }

        Label {
            text: qsTr("Bottom")
            tooltip: qsTr("Padding between the content and the bottom edge of the control.")
        }
        SecondColumnLayout {
            SpinBox {
                maximumValue: 9999999
                minimumValue: -9999999
                decimals: 0
                backendValue: backendValues.bottomPadding
                Layout.fillWidth: true
            }
        }
    }
}
