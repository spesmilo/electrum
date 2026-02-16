// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Camera")

    SectionLayout {
        PropertyLabel {
            text: qsTr("Frustum Culling")
            tooltip: qsTr("When this property is true, objects outside the camera frustum will be culled, meaning they will not be passed to the renderer.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.frustumCullingEnabled.valueToString
                backendValue: backendValues.frustumCullingEnabled
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("LOD Bias")
            tooltip: qsTr("This property changes the threshold for when the automatic level of detail meshes get used.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0.0
                maximumValue: 9999999
                decimals: 2
                backendValue: backendValues.levelOfDetailBias
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Look-at Node")
            tooltip: qsTr("Sets the look-at node for the camera.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.Node"
                backendValue: backendValues.lookAtNode
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
