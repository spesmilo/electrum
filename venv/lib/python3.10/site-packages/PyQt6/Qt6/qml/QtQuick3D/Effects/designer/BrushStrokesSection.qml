// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Column {
    width: parent.width

    Section {
        caption: qsTr("Noise")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Noise Sample Texture")
                tooltip: qsTr("Defines a texture for noise samples.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Texture"
                    backendValue: backendValues.noiseSample_texture
                    defaultItem: qsTr("Default")
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Brush")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Length")
                tooltip: qsTr("Length of the brush.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 3
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.brushLength
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Size")
                tooltip: qsTr("Size of the brush.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 10
                    maximumValue: 200
                    decimals: 0
                    backendValue: backendValues.brushSize
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Angle")
                tooltip: qsTr("Angle of the brush")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 360
                    decimals: 0
                    backendValue: backendValues.brushAngle
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }
}
