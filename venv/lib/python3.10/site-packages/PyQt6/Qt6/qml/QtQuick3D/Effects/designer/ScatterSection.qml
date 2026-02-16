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
        caption: qsTr("Scatter")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Amount")
                tooltip: qsTr("Amount of scatter.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 127
                    decimals: 2
                    backendValue: backendValues.amount
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Direction")
                tooltip: qsTr("Direction of scatter. 0 = both, 1 = horizontal, 2 = vertical.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 2
                    decimals: 0
                    backendValue: backendValues.direction
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Randomize")
                tooltip: qsTr("Specifies if the scatter is random.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.randomize.valueToString
                    backendValue: backendValues.randomize
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }
}
