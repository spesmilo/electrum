// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Custom Material")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Shading Mode")
            tooltip: qsTr("Sets the material type.\nUnshaded materials are not affected by the environment (for example, lights).")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "CustomMaterial"
                model: ["Unshaded", "Shaded"]
                backendValue: backendValues.shadingMode
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Vertex Shader")
            tooltip: qsTr("Sets the path to the vertex shader source file.")
        }

        SecondColumnLayout {
            UrlChooser {
                backendValue: backendValues.vertexShader
                filter: "*.vert *.vsh *.glslv *.glsl"
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Fragment Shader")
            tooltip: qsTr("Sets the path to the fragment shader source file.")
        }

        SecondColumnLayout {
            UrlChooser {
                backendValue: backendValues.fragmentShader
                filter: "*.frag *.fsh *.glslf *.glsl"
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Source Blend")
            tooltip: qsTr("Sets the source blend factor.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "CustomMaterial"
                model: ["NoBlend", "Zero", "One", "SrcColor", "OneMinusSrcColor", "DstColor", "OneMinusDstColor", "SrcAlpha", "OneMinusSrcAlpha", "DstAlpha", "OneMinusDstAlpha", "ConstantColor", "OneMinusConstantColor", "ConstantAlpha", "OneMinusConstantAlpha", "SrcAlphaSaturate"]
                backendValue: backendValues.sourceBlend
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Destination Blend")
            tooltip: qsTr("Sets the destination blend factor.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "CustomMaterial"
                model: ["NoBlend", "Zero", "One", "SrcColor", "OneMinusSrcColor", "DstColor", "OneMinusDstColor", "SrcAlpha", "OneMinusSrcAlpha", "DstAlpha", "OneMinusDstAlpha", "ConstantColor", "OneMinusConstantColor", "ConstantAlpha", "OneMinusConstantAlpha", "SrcAlphaSaturate"]
                backendValue: backendValues.destinationBlend
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

                ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Always Dirty")
            tooltip: qsTr("Sets the material to refresh every time it is used by QtQuick3D.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.alwaysDirty.valueToString
                backendValue: backendValues.alwaysDirty
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Line Width")
            tooltip: qsTr("Sets the width of the lines when the geometry is using a primitive type of lines or line strips.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 1
                maximumValue: 999999
                decimals: 2
                backendValue: backendValues.lineWidth
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
