// Copyright (C) 2023 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Debug Settings")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Enable Wireframe")
            tooltip: qsTr("Meshes will be rendered as wireframes.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.wireframeEnabled.valueToString
                backendValue: backendValues.wireframeEnabled
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

            PropertyLabel {
            text: qsTr("Override Mode")
            tooltip: qsTr("Changes how all materials are rendered to only reflect a particular aspect of the overall rendering process")
        }

        SecondColumnLayout {
            ComboBox {
                id: backgroundModeComboBox
                scope: "DebugSettings"
                model: ["None", "BaseColor", "Roughness", "Metalness", "Diffuse", "Specular", "ShadowOcclusion", "Emission", "AmbientOcclusion", "Normals", "Tangents", "Binormals", "FO"]
                backendValue: backendValues.materialOverride
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
