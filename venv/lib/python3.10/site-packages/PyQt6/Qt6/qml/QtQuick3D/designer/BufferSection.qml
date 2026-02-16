// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Buffer")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Name")
            tooltip: qsTr("Sets the buffer name.")
        }

        SecondColumnLayout {
            LineEdit {
                backendValue: backendValues.name
                showTranslateCheckBox: false
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                width: implicitWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Format")
            tooltip: qsTr("Sets the format of the buffer.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "Buffer"
                model: ["Unknown", "R8", "R16", "R16F", "R32I", "R32UI", "R32F", "RG8", "RGBA8", "RGB8", "SRGB8", "SRGB8A8", "RGB565", "RGBA16F", "RG16F", "RG32F", "RGB32F", "RGBA32F", "R11G11B10", "RGB9E5", "Depth16", "Depth24", "Depth32", "Depth24Stencil8"]
                backendValue: backendValues.format
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Filter")
            tooltip: qsTr("Sets the texture filter for the buffer.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "Buffer"
                model: ["Unknown", "Nearest", "Linear"]
                backendValue: backendValues.textureFilterOperation
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Coordinate Operation")
            tooltip: qsTr("Sets the texture coordinate operation for the buffer.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "Buffer"
                model: ["Unknown", "ClampToEdge", "MirroredRepeat", "Repeat"]
                backendValue: backendValues.textureCoordOperation
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Allocation Flags")
            tooltip: qsTr("Sets the allocation flags for the buffer.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "Buffer"
                model: ["None", "SceneLifetime"]
                backendValue: backendValues.bufferFlags
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Size Multiplier")
            tooltip: qsTr("Sets the size multiplier for the buffer.")
        }

        SecondColumnLayout {
            SpinBox {
                maximumValue: 10000
                minimumValue: 0
                decimals: 2
                realDragRange: 30
                backendValue: backendValues.sizeMultiplier
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
