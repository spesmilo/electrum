// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only WITH Qt-GPL-exception-1.0

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick3D
import QtQuick3D.MaterialEditor

Pane {
    id: root
    required property MaterialAdapter targetMaterial

    ColumnLayout {
        RowLayout {
            Label {
                text: qsTr("Source Blend")
                Layout.fillWidth: true
            }
            ComboBox {
                id: sourceBlendComboBox
                textRole: "text"
                valueRole: "value"
                implicitContentWidthPolicy: ComboBox.WidestText
                onActivated: root.targetMaterial.sourceBlend = currentValue
                Component.onCompleted: currentIndex = indexOfValue(root.targetMaterial.sourceBlend)
                model: [
                    { value: CustomMaterial.NoBlend, text: qsTr("No Blend") },
                    { value: CustomMaterial.Zero, text: qsTr("Zero") },
                    { value: CustomMaterial.One, text: qsTr("One") },
                    { value: CustomMaterial.SrcColor, text: qsTr("Source Color") },
                    { value: CustomMaterial.OneMinusSrcColor, text: qsTr("1 - Source Color") },
                    { value: CustomMaterial.DstColor, text: qsTr("Destination Color") },
                    { value: CustomMaterial.OneMinusDstColor, text: qsTr("1 - Destination Color") },
                    { value: CustomMaterial.SrcAlpha, text: qsTr("Source Alpha") },
                    { value: CustomMaterial.OneMinusSrcAlpha, text: qsTr("1 - Source Alpha") },
                    { value: CustomMaterial.DstAlpha, text: qsTr("Destination Alpha") },
                    { value: CustomMaterial.OneMinusDstAlpha, text: qsTr("1 - Destination Alpha") },
                    { value: CustomMaterial.ConstantColor, text: qsTr("Constant Color") },
                    { value: CustomMaterial.OneMinusConstantColor, text: qsTr("1 - Constant Color") },
                    { value: CustomMaterial.ConstantAlpha, text: qsTr("Constant Alpha") },
                    { value: CustomMaterial.OneMinusConstantAlpha, text: qsTr("1 - Constant Alpha") },
                    { value: CustomMaterial.SrcAlphaSaturate, text: qsTr("Source Alpha Saturate") }
                ]
            }
        }
        RowLayout {
            Label {
                text: qsTr("Destination Blend")
                Layout.fillWidth: true
            }
            ComboBox {
                id: destinationBlendComboBox
                textRole: "text"
                valueRole: "value"
                implicitContentWidthPolicy: ComboBox.WidestText
                onActivated: root.targetMaterial.destinationBlend = currentValue
                Component.onCompleted: currentIndex = indexOfValue(root.targetMaterial.destinationBlend)

                model: [
                    { value: CustomMaterial.NoBlend, text: qsTr("No Blend") },
                    { value: CustomMaterial.Zero, text: qsTr("Zero") },
                    { value: CustomMaterial.One, text: qsTr("One") },
                    { value: CustomMaterial.SrcColor, text: qsTr("Source Color") },
                    { value: CustomMaterial.OneMinusSrcColor, text: qsTr("1 - Source Color") },
                    { value: CustomMaterial.DstColor, text: qsTr("Destination Color") },
                    { value: CustomMaterial.OneMinusDstColor, text: qsTr("1 - Destination Color") },
                    { value: CustomMaterial.SrcAlpha, text: qsTr("Source Alpha") },
                    { value: CustomMaterial.OneMinusSrcAlpha, text: qsTr("1 - Source Alpha") },
                    { value: CustomMaterial.DstAlpha, text: qsTr("Destination Alpha") },
                    { value: CustomMaterial.OneMinusDstAlpha, text: qsTr("1 - Destination Alpha") },
                    { value: CustomMaterial.ConstantColor, text: qsTr("Constant Color") },
                    { value: CustomMaterial.OneMinusConstantColor, text: qsTr("1 - Constant Color") },
                    { value: CustomMaterial.ConstantAlpha, text: qsTr("Constant Alpha") },
                    { value: CustomMaterial.OneMinusConstantAlpha, text: qsTr("1 - Constant Alpha") },
                    { value: CustomMaterial.SrcAlphaSaturate, text: qsTr("Source Alpha Saturate") }
                ]
            }
        }
        RowLayout {
            Label {
                text: qsTr("Cull Mode")
                Layout.fillWidth: true
            }
            ComboBox {
                id: cullModeComboBox
                textRole: "text"
                valueRole: "value"
                implicitContentWidthPolicy: ComboBox.WidestText
                onActivated: root.targetMaterial.cullMode = currentValue
                Component.onCompleted: currentIndex = indexOfValue(root.targetMaterial.cullMode)
                model: [
                    { value: CustomMaterial.BackFaceCulling, text: qsTr("Back Face Culling") },
                    { value: CustomMaterial.FrontFaceCulling, text: qsTr("Front Face Culling") },
                    { value: CustomMaterial.NoCulling, text: qsTr("No Culling") }
                ]
            }
        }
        RowLayout {
            Label {
                text: qsTr("Depth Draw Mode")
                Layout.fillWidth: true
            }
            ComboBox {
                id: depthDrawModeComboBox
                textRole: "text"
                valueRole: "value"
                implicitContentWidthPolicy: ComboBox.WidestText
                onActivated: root.targetMaterial.depthDrawMode = currentValue
                Component.onCompleted: currentIndex = indexOfValue(root.targetMaterial.depthDrawMode)
                model: [
                    { value: CustomMaterial.OpaqueOnlyDepthDraw, text: qsTr("Opaque Only") },
                    { value: CustomMaterial.AlwaysDepthDraw, text: qsTr("Always") },
                    { value: CustomMaterial.NeverDepthDraw, text: qsTr("Never") },
                    { value: CustomMaterial.OpaquePrePassDepthDraw, text: qsTr("Opaque Pre-pass") }
                ]
            }
        }
        RowLayout {
            Label {
                text: qsTr("Shading Mode")
                Layout.fillWidth: true
            }
            ComboBox {
                id: shadingModeComboBox
                textRole: "text"
                valueRole: "value"
                implicitContentWidthPolicy: ComboBox.WidestText
                onActivated: root.targetMaterial.shadingMode = currentValue
                Component.onCompleted: currentIndex = indexOfValue(root.targetMaterial.shadingMode)
                model: [
                    { value: CustomMaterial.Shaded, text: qsTr("Shaded") },
                    { value: CustomMaterial.Unshaded, text: qsTr("Unshaded") }
                ]
            }
        }
    }
}
