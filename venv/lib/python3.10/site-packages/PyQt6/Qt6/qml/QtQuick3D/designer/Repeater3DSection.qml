// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Repeater")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Model")
            tooltip: qsTr("The model providing data for the repeater. This can simply specify the number of delegate instances to create or it can be bound to an actual model.")
        }

        SecondColumnLayout {
            LineEdit {
                backendValue: backendValues.model
                showTranslateCheckBox: false
                writeAsExpression: true
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
                width: implicitWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Delegate")
            tooltip: qsTr("The delegate provides a template defining each object instantiated by the repeater.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "Component"
                backendValue: backendValues.delegate
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
