// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("View3D")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Camera")
            tooltip: qsTr("Sets which camera is used to render the scene.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.Camera"
                backendValue: backendValues.camera
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Environment")
            tooltip: qsTr("Sets the scene environment used to render the scene.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.SceneEnvironment"
                backendValue: backendValues.environment
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Import Scene")
            tooltip: qsTr("Sets the reference node of the scene to render to the viewport.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.Node"
                backendValue: backendValues.importScene
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Render Format")
            tooltip: qsTr("Sets the format of the backing texture.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "ShaderEffectSource"
                model: ["RGBA8", "RGBA16F", "RGBA32F"]
                backendValue: backendValues.renderFormat
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
