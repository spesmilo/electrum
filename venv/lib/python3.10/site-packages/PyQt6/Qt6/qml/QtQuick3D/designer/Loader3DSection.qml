// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Loader3D")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Active")
            tooltip: qsTr("Sets if the Loader3D is currently active.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.active.valueToString
                backendValue: backendValues.active
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Source")
            tooltip: qsTr("Sets the URL of the QML component to instantiate.")
        }

        SecondColumnLayout {
            UrlChooser {
                filter: "*.qml"
                backendValue:  backendValues.source
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Source Component")
            tooltip: qsTr("Sets the component to instantiate.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "Component"
                backendValue: backendValues.sourceComponent
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Asynchronous")
            tooltip: qsTr("Sets whether the component will be instantiated asynchronously.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.asynchronous.valueToString
                backendValue: backendValues.asynchronous
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
