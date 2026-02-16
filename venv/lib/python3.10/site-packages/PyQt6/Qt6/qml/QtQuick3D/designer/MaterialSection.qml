// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Material")

    SectionLayout {

        // Baked Lighting properties (may be internal eventually)
        // ### lightmapIndirect
        // ### lightmapRadiosity
        // ### lightmapShadow

        // ### iblProbe override

        PropertyLabel {
            text: qsTr("Light Probe")
            tooltip: qsTr("Sets a texture to use as image based lighting.\nThis overrides the scene's light probe.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.Texture"
                backendValue: backendValues.lightProbe
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Culling Mode")
            tooltip: qsTr("Sets which primitives to discard, if any.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "Material"
                model: ["BackFaceCulling", "FrontFaceCulling", "NoCulling"]
                backendValue: backendValues.cullMode
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Depth Draw Mode")
            tooltip: qsTr("Sets if and when depth rendering takes place.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "Material"
                model: ["OpaqueOnlyDepthDraw", "AlwaysDepthDraw", "NeverDepthDraw", "OpaquePrePassDepthDraw"]
                backendValue: backendValues.depthDrawMode
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
