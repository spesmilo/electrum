// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Set Uniform Value")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Target")
            tooltip: qsTr("Sets the name of the uniform to change value for a pass.")
        }

        SecondColumnLayout {
            LineEdit {
                backendValue: backendValues.target
                showTranslateCheckBox: false
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
                width: implicitWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Value")
            tooltip: qsTr("Sets the value of the uniform.")
        }

        SecondColumnLayout {
            LineEdit {
                backendValue: backendValues.value
                showTranslateCheckBox: false
                writeAsExpression: true
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
                width: implicitWidth
            }

            ExpandingSpacer {}
        }
    }
}
