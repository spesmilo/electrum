// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Texture")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Source")
            tooltip: qsTr("Sets the location of an image file containing the data used by the texture.")
        }

        SecondColumnLayout {
            UrlChooser {
                backendValue: backendValues.source
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Source Item")
            tooltip: qsTr("Sets an item to be used as the source of the texture.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick.Item"
                backendValue: backendValues.sourceItem
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
        PropertyLabel {
            text: qsTr("Texture Data")
            tooltip: qsTr("Sets a reference to a TextureData component which defines the contents and properties of raw texture data.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.TextureData"
                backendValue: backendValues.textureData
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Scale")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 999999
                decimals: 2
                backendValue: backendValues.scaleU
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "U"
                tooltip: qsTr("Sets how to scale the U texture coordinate when mapping to UV coordinates of a mesh.")
            }

            Spacer { implicitWidth: StudioTheme.Values.controlGap }

            SpinBox {
                minimumValue: 0
                maximumValue: 999999
                decimals: 2
                backendValue: backendValues.scaleV
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "V"
                tooltip: qsTr("Sets how to scale the V texture coordinate when mapping to UV coordinates of a mesh.")
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Flip V")
            tooltip: qsTr("Sets the use of the vertically flipped coordinates.")
        }

        SecondColumnLayout {
            CheckBox {
                id: flipVcheckBox
                text: backendValues.flipV.valueToString
                backendValue: backendValues.flipV
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Flip U")
            tooltip: qsTr("Sets the use of the horizontally flipped texture coordinates.")
        }

        SecondColumnLayout {
            CheckBox {
                id: flipUCheckBox
                text: backendValues.flipU.valueToString
                backendValue: backendValues.flipU
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Auto Orientation")
            tooltip: qsTr("Sets if a texture transformation, such as flipping the V texture coordinate, is applied automatically for textures where this is typically relevant.")
        }

        SecondColumnLayout {
            CheckBox {
                id: autoOrientationCheckBox
                text: backendValues.autoOrientation.valueToString
                backendValue: backendValues.autoOrientation
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Texture Mapping")
            tooltip: qsTr("Sets which method of mapping to use when sampling this texture.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "Texture"
                model: ["UV", "Environment", "LightProbe"]
                backendValue: backendValues.mappingMode
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }
        }

        PropertyLabel {
            text: qsTr("U Tiling")
            tooltip: qsTr("Sets how the texture is mapped when the U scaling value is greater than 1.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "Texture"
                model: ["ClampToEdge", "MirroredRepeat", "Repeat"]
                backendValue: backendValues.tilingModeHorizontal
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("V Tiling")
            tooltip: qsTr("Sets how the texture is mapped when the V scaling value is greater than 1.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "Texture"
                model: ["ClampToEdge", "MirroredRepeat", "Repeat"]
                backendValue: backendValues.tilingModeVertical
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("UV Index")
            tooltip: qsTr("Sets the UV coordinate index used by this texture.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 999999
                decimals: 0
                backendValue: backendValues.indexUV
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("UV Rotation")
            tooltip: qsTr("Sets the rotation of the texture around the pivot point.")
        }

        SecondColumnLayout {
            SpinBox {
                maximumValue: 999999
                minimumValue: -999999
                decimals: 0
                backendValue: backendValues.rotationUV
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Position")
        }

        SecondColumnLayout {
            SpinBox {
                maximumValue: 999999
                minimumValue: -999999
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.positionU
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "U"
                tooltip: qsTr("Sets the U coordinate mapping offset from left to right.")
            }

            Spacer { implicitWidth: StudioTheme.Values.controlGap }

            SpinBox {
                maximumValue: 999999
                minimumValue: -999999
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.positionV
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "V"
                tooltip: qsTr("Sets the V coordinate mapping offset from bottom to top.")
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Pivot")
        }

        SecondColumnLayout {
            SpinBox {
                maximumValue: 999999
                minimumValue: -999999
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.pivotU
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "U"
                tooltip: qsTr("Sets the pivot U position.")
            }

            Spacer { implicitWidth: StudioTheme.Values.controlGap }

            SpinBox {
                maximumValue: 999999
                minimumValue: -999999
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.pivotV
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "V"
                tooltip: qsTr("Sets the pivot V position.")
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Generate Mipmaps")
            tooltip: qsTr("Sets if mipmaps are generated for textures that do not provide mipmap levels themselves.")
        }

        SecondColumnLayout {
            CheckBox {
                id: generateMipmapscheckBox
                text: backendValues.generateMipmaps.valueToString
                backendValue: backendValues.generateMipmaps
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Mag Filter")
            tooltip: qsTr("Sets how the texture is sampled when a texel covers more than one pixel.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "Texture"
                model: ["None", "Nearest", "Linear"]
                backendValue: backendValues.magFilter
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Min Filter")
            tooltip: qsTr("Sets how the texture is sampled when a texel covers more than one pixel.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "Texture"
                model: ["None", "Nearest", "Linear"]
                backendValue: backendValues.minFilter
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Mip Filter")
            tooltip: qsTr("Sets how the texture mipmaps are sampled when a texel covers less than one pixel.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "Texture"
                model: ["None", "Nearest", "Linear"]
                backendValue: backendValues.mipFilter
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
